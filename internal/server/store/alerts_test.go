package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

// alertFixture builds a channel and a rule that delivers to it.
func alertFixture(t *testing.T, q *store.Queries, kind string) (store.NotificationChannel, store.AlertRule) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	ch := store.NotificationChannel{
		ID: uuid.Must(uuid.NewV7()), Name: "Ops " + kind, Kind: store.ChannelWebhook,
		Config: []byte(`{"url":"https://hooks.example.com/retune"}`), Enabled: true,
		CreatedAt: now, UpdatedAt: now, CreatedBy: "test",
	}
	if err := q.CreateNotificationChannel(ctx, ch); err != nil {
		t.Fatal(err)
	}
	rule := store.AlertRule{
		ID: uuid.Must(uuid.NewV7()), Name: "Rule " + kind, Kind: kind, Params: []byte(`{}`),
		ChannelID: ch.ID, Enabled: true, CreatedAt: now, UpdatedAt: now, CreatedBy: "test",
	}
	if err := q.CreateAlertRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	return ch, rule
}

func TestDeletingAChannelAnAlertRuleUsesIsRefused(t *testing.T) {
	ctx := context.Background()
	q := storetest.New(t).Q()
	ch, rule := alertFixture(t, q, store.AlertDeviceStale)

	// Silently deleting the rules with the channel would silently stop the
	// alerting, which is the one failure alerting cannot afford.
	if err := q.DeleteNotificationChannel(ctx, store.DefaultTenantID, ch.ID); !errors.Is(err, store.ErrInUse) {
		t.Fatalf("delete channel in use = %v, want ErrInUse", err)
	}
	if err := q.DeleteAlertRule(ctx, store.DefaultTenantID, rule.ID); err != nil {
		t.Fatal(err)
	}
	if err := q.DeleteNotificationChannel(ctx, store.DefaultTenantID, ch.ID); err != nil {
		t.Fatalf("delete channel once unused: %v", err)
	}
}

func TestAlertRuleAndChannelNamesAreUnique(t *testing.T) {
	ctx := context.Background()
	q := storetest.New(t).Q()
	ch, rule := alertFixture(t, q, store.AlertDeviceStale)

	dup := ch
	dup.ID = uuid.Must(uuid.NewV7())
	if err := q.CreateNotificationChannel(ctx, dup); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate channel name = %v, want ErrDuplicate", err)
	}
	dupRule := rule
	dupRule.ID = uuid.Must(uuid.NewV7())
	if err := q.CreateAlertRule(ctx, dupRule); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate rule name = %v, want ErrDuplicate", err)
	}
}

func TestAlertStateIsTheDeduplication(t *testing.T) {
	ctx := context.Background()
	q := storetest.New(t).Q()
	_, rule := alertFixture(t, q, store.AlertDeviceStale)
	now := time.Now().UTC().Truncate(time.Microsecond)

	first := store.AlertSubject{Key: "device:a", Subject: "PC-A has never checked in"}
	if err := q.InsertAlertState(ctx, rule.ID, first, now); err != nil {
		t.Fatal(err)
	}
	if err := q.MarkAlertsNotified(ctx, rule.ID, []string{first.Key}, now); err != nil {
		t.Fatal(err)
	}

	// The same subject on a later tick keeps the moment the problem started,
	// which is what stops a long-running fault re-alerting every five minutes.
	later := now.Add(time.Hour)
	reworded := store.AlertSubject{Key: first.Key, Subject: "PC-A has not checked in since yesterday"}
	if err := q.InsertAlertState(ctx, rule.ID, reworded, later); err != nil {
		t.Fatal(err)
	}
	state, err := q.ListAlertState(ctx, rule.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := state[first.Key]
	if !ok {
		t.Fatalf("state = %+v, want the subject still firing", state)
	}
	if !got.FiringSince.Equal(now) {
		t.Errorf("firing_since = %s, want it unchanged at %s", got.FiringSince, now)
	}
	if got.Subject != reworded.Subject {
		t.Errorf("subject = %q, want it refreshed to %q", got.Subject, reworded.Subject)
	}
	if got.NotifiedAt == nil {
		t.Error("notified_at was cleared; a second message would be sent for the same fault")
	}

	if err := q.DeleteAlertState(ctx, rule.ID, []string{first.Key}); err != nil {
		t.Fatal(err)
	}
	if state, err := q.ListAlertState(ctx, rule.ID); err != nil || len(state) != 0 {
		t.Fatalf("after resolve: %+v %v", state, err)
	}
}

func TestFiringQueriesFindOnlyActiveDevices(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	q := s.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)

	mk := func(hostname, status string, seen *time.Time) store.Device {
		d := store.Device{
			ID: uuid.Must(uuid.NewV7()), Hostname: hostname, Status: status,
			CertSerial: "c", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
		}
		if err := q.CreateDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		if seen != nil {
			if err := q.RecordCheckin(ctx, store.DefaultTenantID, d.ID, "0.3.0", *seen); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	fresh := now.Add(-time.Minute)
	old := now.Add(-48 * time.Hour)
	quiet := mk("PC-QUIET", store.DeviceActive, &old)
	mk("PC-BUSY", store.DeviceActive, &fresh)
	never := mk("PC-NEVER", store.DeviceActive, nil)
	// A retired machine is not a machine anybody is going to go and fix.
	mk("PC-GONE", store.DeviceRetired, &old)

	stale, err := q.FiringStaleDevices(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, subject := range stale {
		keys[subject.Key] = subject.Subject
	}
	if len(keys) != 2 {
		t.Fatalf("stale = %+v, want PC-QUIET and PC-NEVER only", stale)
	}
	if _, ok := keys["device:"+quiet.ID.String()]; !ok {
		t.Errorf("stale = %+v, want the quiet device", stale)
	}
	if subject := keys["device:"+never.ID.String()]; subject != "PC-NEVER has never checked in" {
		t.Errorf("never-seen subject = %q", subject)
	}

	// Deployment failures are per failing item, not per device: two broken
	// scripts on one machine are two things to fix.
	for _, item := range []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())} {
		if err := q.SetItemStatus(ctx, store.ItemStatus{
			DeviceID: quiet.ID, ItemKind: "script", ItemID: item,
			Status: "failed", Detail: "exit code 1", UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.SetItemStatus(ctx, store.ItemStatus{
		DeviceID: never.ID, ItemKind: "app", ItemID: uuid.Must(uuid.NewV7()),
		Status: "succeeded", UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	failed, err := q.FiringFailedDeployments(ctx, "")
	if err != nil || len(failed) != 2 {
		t.Fatalf("failed deployments = %+v, err = %v, want 2", failed, err)
	}
	if none, err := q.FiringFailedDeployments(ctx, "app"); err != nil || len(none) != 0 {
		t.Fatalf("app failures = %+v, err = %v, want none", none, err)
	}
}

func TestFiringNonCompliantDevicesNamesThePolicies(t *testing.T) {
	ctx := context.Background()
	q := storetest.New(t).Q()
	now := time.Now().UTC().Truncate(time.Microsecond)

	device := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: "PC-FAIL", Status: store.DeviceActive,
		CertSerial: "c", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := q.CreateDevice(ctx, device); err != nil {
		t.Fatal(err)
	}
	mkPolicy := func(name string) store.CompliancePolicy {
		p := store.CompliancePolicy{
			ID: uuid.Must(uuid.NewV7()), Name: name, Rules: []byte(`[]`),
			CreatedAt: now, UpdatedAt: now, CreatedBy: "test",
		}
		if err := q.CreateCompliancePolicy(ctx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	encryption := mkPolicy("Encryption")
	baseline := mkPolicy("Baseline")
	for _, tc := range []struct {
		policy store.CompliancePolicy
		state  string
	}{{encryption, store.ComplianceNonCompliant}, {baseline, store.ComplianceNonCompliant}} {
		if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{
			DeviceID: device.ID, PolicyID: tc.policy.ID, State: tc.state,
			Failures: []byte(`[]`), EvaluatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	all, err := q.FiringNonCompliantDevices(ctx, nil)
	if err != nil || len(all) != 1 {
		t.Fatalf("firing = %+v, err = %v, want one device", all, err)
	}
	// One subject per device however many policies it fails, and the policies
	// named in a stable order so the same fault reads the same way twice.
	if want := "PC-FAIL is non-compliant with Baseline, Encryption"; all[0].Subject != want {
		t.Errorf("subject = %q, want %q", all[0].Subject, want)
	}

	one, err := q.FiringNonCompliantDevices(ctx, &baseline.ID)
	if err != nil || len(one) != 1 {
		t.Fatalf("one policy = %+v, err = %v", one, err)
	}
	if want := "PC-FAIL is non-compliant with Baseline"; one[0].Subject != want {
		t.Errorf("subject = %q, want %q", one[0].Subject, want)
	}
}
