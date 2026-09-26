package app_test

import (
	"context"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/adminapi"
	"retune/internal/server/store"
)

// TestDeviceListFilters covers how GET /devices reads its query: status
// active, stale and retired are the console's buckets (active split by
// whether the device has checked in within StaleAfter), any other status is
// matched exactly, and compliance filters on the device's overall state.
func TestDeviceListFilters(t *testing.T) {
	ctx := context.Background()
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	q := a.Store.Q()
	now := time.Now().UTC()

	fresh, _ := enrollDevice(t, a, srv, "PC-FRESH")
	stale, _ := enrollDevice(t, a, srv, "PC-STALE")
	edge, _ := enrollDevice(t, a, srv, "PC-EDGE")
	retired, _ := enrollDevice(t, a, srv, "PC-RETIRED")
	gone, _ := enrollDevice(t, a, srv, "PC-GONE")
	// Never checked in at all: stale, not active.
	never := store.Device{
		ID: uuid.Must(uuid.NewV7()), Hostname: "PC-NEVER", Status: store.DeviceActive,
		CertSerial: "c", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
	}
	if err := q.CreateDevice(ctx, never); err != nil {
		t.Fatal(err)
	}
	for id, seen := range map[uuid.UUID]time.Time{
		fresh:   now,
		stale:   now.Add(-adminapi.StaleAfter - time.Hour),
		edge:    now.Add(-adminapi.StaleAfter + time.Hour),
		retired: now,
		gone:    now,
	} {
		if err := q.RecordCheckin(ctx, store.DefaultTenantID, id, "1.0.0", seen); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.SetDeviceStatus(ctx, store.DefaultTenantID, retired, store.DeviceRetired); err != nil {
		t.Fatal(err)
	}
	if err := q.SetDeviceStatus(ctx, store.DefaultTenantID, gone, store.DeviceUnenrolled); err != nil {
		t.Fatal(err)
	}

	policy := store.CompliancePolicy{
		ID: uuid.Must(uuid.NewV7()), Name: "Baseline", Rules: []byte(`[]`),
		CreatedAt: now, UpdatedAt: now, CreatedBy: "test",
	}
	if err := q.CreateCompliancePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	for id, state := range map[uuid.UUID]string{
		fresh: store.ComplianceCompliant,
		stale: store.ComplianceNonCompliant,
	} {
		if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{
			DeviceID: id, PolicyID: policy.ID, State: state, Failures: []byte(`[]`), EvaluatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	type listed struct {
		Items []struct {
			Hostname string `json:"hostname"`
			Stale    bool   `json:"stale"`
		} `json:"items"`
		Total int `json:"total"`
	}
	list := func(query string) []string {
		t.Helper()
		status, body := admin.do(http.MethodGet, "/devices?"+query, nil)
		if status != http.StatusOK {
			t.Fatalf("list %s: %d %s", query, status, body)
		}
		got := decodeJSON[listed](t, body)
		names := make([]string, 0, len(got.Items))
		for _, it := range got.Items {
			names = append(names, it.Hostname)
		}
		if got.Total != len(names) {
			t.Errorf("%s: total %d, but %d items", query, got.Total, len(names))
		}
		sort.Strings(names)
		return names
	}
	cases := []struct {
		query string
		want  []string
	}{
		{"", []string{"PC-EDGE", "PC-FRESH", "PC-GONE", "PC-NEVER", "PC-RETIRED", "PC-STALE"}},
		// Buckets.
		{"status=active", []string{"PC-EDGE", "PC-FRESH"}},
		{"status=stale", []string{"PC-NEVER", "PC-STALE"}},
		{"status=retired", []string{"PC-GONE", "PC-RETIRED"}},
		// Any other status is matched exactly.
		{"status=unenrolled", []string{"PC-GONE"}},
		{"status=replaced", []string{}},
		// Compliance, alone and with a bucket.
		{"compliance=compliant", []string{"PC-FRESH"}},
		{"compliance=non_compliant", []string{"PC-STALE"}},
		{"compliance=not_evaluated", []string{"PC-EDGE", "PC-GONE", "PC-NEVER", "PC-RETIRED"}},
		{"status=stale&compliance=non_compliant", []string{"PC-STALE"}},
		{"status=active&compliance=non_compliant", []string{}},
		// With a search.
		{"status=active&search=fresh", []string{"PC-FRESH"}},
	}
	for _, c := range cases {
		got := list(c.query)
		if len(got) != len(c.want) {
			t.Errorf("%q = %v, want %v", c.query, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q = %v, want %v", c.query, got, c.want)
				break
			}
		}
	}
}
