package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestCompliancePolicyRoundTrip(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)

	p := store.CompliancePolicy{
		ID: uuid.Must(uuid.NewV7()), Name: "Baseline", Description: "minimum bar",
		Rules:     json.RawMessage(`[{"type":"bitlocker","volumes":"system"}]`),
		CreatedAt: now, UpdatedAt: now, CreatedBy: "ops",
	}
	if err := q.CreateCompliancePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	got, err := q.GetCompliancePolicy(ctx, store.DefaultTenantID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	// jsonb re-serializes (e.g. adds spaces after ":" and ","), so compare
	// decoded values rather than raw bytes.
	if got.Name != "Baseline" || got.Description != "minimum bar" || !jsonEqual(t, got.Rules, p.Rules) {
		t.Fatalf("policy = %+v", got)
	}

	list, total, err := q.ListCompliancePolicies(ctx, store.Page{})
	if err != nil || total != 1 || len(list) != 1 || list[0].ID != p.ID {
		t.Fatalf("list: %v total=%d list=%+v", err, total, list)
	}

	got.Name = "Baseline v2"
	got.Description = "still the minimum bar"
	got.Rules = json.RawMessage(`[{"type":"tpm"}]`)
	got.UpdatedAt = now.Add(time.Hour)
	if err := q.UpdateCompliancePolicy(ctx, store.DefaultTenantID, got); err != nil {
		t.Fatal(err)
	}
	updated, err := q.GetCompliancePolicy(ctx, store.DefaultTenantID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Baseline v2" || !jsonEqual(t, updated.Rules, json.RawMessage(`[{"type":"tpm"}]`)) {
		t.Fatalf("updated = %+v", updated)
	}

	if err := q.DeleteCompliancePolicy(ctx, store.DefaultTenantID, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetCompliancePolicy(ctx, store.DefaultTenantID, p.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after deletion it should be gone, got %v", err)
	}
}

func TestCompliancePolicyDuplicateName(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC()

	p := store.CompliancePolicy{ID: uuid.Must(uuid.NewV7()), Name: "Dup", Rules: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now, CreatedBy: "ops"}
	if err := q.CreateCompliancePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	dup := p
	dup.ID = uuid.Must(uuid.NewV7())
	if err := q.CreateCompliancePolicy(ctx, dup); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("want ErrDuplicate, got %v", err)
	}

	// Renaming a second policy onto an existing name is the same clash, just
	// caught by the update path instead of the insert path.
	other := store.CompliancePolicy{ID: uuid.Must(uuid.NewV7()), Name: "Other", Rules: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now, CreatedBy: "ops"}
	if err := q.CreateCompliancePolicy(ctx, other); err != nil {
		t.Fatal(err)
	}
	other.Name = "Dup"
	other.UpdatedAt = now.Add(time.Minute)
	if err := q.UpdateCompliancePolicy(ctx, store.DefaultTenantID, other); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("want ErrDuplicate on rename clash, got %v", err)
	}
}

func TestCompliancePolicyQueriesAreScopedByTenant(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC()
	p := store.CompliancePolicy{ID: uuid.Must(uuid.NewV7()), Name: "Scoped", Rules: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now, CreatedBy: "ops"}
	if err := q.CreateCompliancePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	other := uuid.Must(uuid.NewV7())

	if _, err := q.GetCompliancePolicy(ctx, other, p.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another tenant must not see the row: %v", err)
	}
	if err := q.UpdateCompliancePolicy(ctx, other, p); err != nil {
		t.Fatal(err)
	}
	if got, err := q.GetCompliancePolicy(ctx, store.DefaultTenantID, p.ID); err != nil || got.Name != "Scoped" {
		t.Errorf("another tenant must not update the row: %v %+v", err, got)
	}
	if err := q.DeleteCompliancePolicy(ctx, other, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetCompliancePolicy(ctx, store.DefaultTenantID, p.ID); err != nil {
		t.Errorf("another tenant must not delete the row: %v", err)
	}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatal(err)
	}
	am, _ := json.Marshal(av)
	bm, _ := json.Marshal(bv)
	return string(am) == string(bm)
}

func newPolicy(t *testing.T, q *store.Queries, name string) store.CompliancePolicy {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := store.CompliancePolicy{ID: uuid.Must(uuid.NewV7()), Name: name, Rules: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now, CreatedBy: "ops"}
	if err := q.CreateCompliancePolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestListDeviceComplianceNamesAndOrdersPolicies covers what the device
// detail page reads: each row carries its policy's name, and the rows arrive
// by name rather than by the id the page never shows.
func TestListDeviceComplianceNamesAndOrdersPolicies(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	dev := newDevice(t, q, "h1")
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Created out of alphabetical order, and mixed case, so neither insertion
	// order nor a case-sensitive sort would produce the wanted order.
	for _, name := range []string{"zebra", "Apple", "mango"} {
		p := newPolicy(t, q, name)
		if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{
			DeviceID: dev.ID, PolicyID: p.ID, State: store.ComplianceCompliant,
			Failures: json.RawMessage(`[]`), EvaluatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	list, err := q.ListDeviceCompliance(ctx, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, dc := range list {
		got = append(got, dc.PolicyName)
	}
	want := []string{"Apple", "mango", "zebra"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestDeviceComplianceRoundTripAndDeleteExcept(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	dev := newDevice(t, q, "h1")
	polA := newPolicy(t, q, "A")
	polB := newPolicy(t, q, "B")
	now := time.Now().UTC().Truncate(time.Microsecond)

	if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{
		DeviceID: dev.ID, PolicyID: polA.ID, State: store.ComplianceNonCompliant,
		Failures:    json.RawMessage(`[{"rule":"bitlocker","state":"non_compliant","detail":"BitLocker is off on C:"}]`),
		EvaluatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{
		DeviceID: dev.ID, PolicyID: polB.ID, State: store.ComplianceUnknown,
		Failures: json.RawMessage(`[]`), EvaluatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	list, err := q.ListDeviceCompliance(ctx, dev.ID)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v %+v", err, list)
	}

	// Re-upserting the same (device, policy) updates in place rather than
	// adding a second row.
	if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{
		DeviceID: dev.ID, PolicyID: polA.ID, State: store.ComplianceCompliant,
		Failures: json.RawMessage(`[]`), EvaluatedAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	list, err = q.ListDeviceCompliance(ctx, dev.ID)
	if err != nil || len(list) != 2 {
		t.Fatalf("list after re-upsert: %v %+v", err, list)
	}

	// Policy A no longer applies: its row is removed, B's stays.
	if err := q.DeleteDeviceComplianceExcept(ctx, dev.ID, []uuid.UUID{polB.ID}); err != nil {
		t.Fatal(err)
	}
	list, err = q.ListDeviceCompliance(ctx, dev.ID)
	if err != nil || len(list) != 1 || list[0].PolicyID != polB.ID {
		t.Fatalf("after delete except: %v %+v", err, list)
	}

	// Nothing kept means nothing applies any more: every row goes.
	if err := q.DeleteDeviceComplianceExcept(ctx, dev.ID, nil); err != nil {
		t.Fatal(err)
	}
	list, err = q.ListDeviceCompliance(ctx, dev.ID)
	if err != nil || len(list) != 0 {
		t.Fatalf("after delete except nil keep: %v %+v", err, list)
	}
}

func TestDeleteComplianceForPolicy(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	dev1 := newDevice(t, q, "h1")
	dev2 := newDevice(t, q, "h2")
	pol := newPolicy(t, q, "P")
	now := time.Now().UTC()

	for _, dev := range []store.Device{dev1, dev2} {
		if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{
			DeviceID: dev.ID, PolicyID: pol.ID, State: store.ComplianceCompliant,
			Failures: json.RawMessage(`[]`), EvaluatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.DeleteComplianceForPolicy(ctx, pol.ID); err != nil {
		t.Fatal(err)
	}
	for _, dev := range []store.Device{dev1, dev2} {
		list, err := q.ListDeviceCompliance(ctx, dev.ID)
		if err != nil || len(list) != 0 {
			t.Fatalf("expected no rows for %s after policy deletion: %v %+v", dev.Hostname, err, list)
		}
	}
}

func TestListPolicyCompliance(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	pol := newPolicy(t, q, "P")
	zeta := newDevice(t, q, "zeta")
	alpha := newDevice(t, q, "alpha")
	now := time.Now().UTC()

	if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{DeviceID: zeta.ID, PolicyID: pol.ID, State: store.ComplianceNonCompliant, Failures: json.RawMessage(`[]`), EvaluatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{DeviceID: alpha.ID, PolicyID: pol.ID, State: store.ComplianceCompliant, Failures: json.RawMessage(`[]`), EvaluatedAt: now}); err != nil {
		t.Fatal(err)
	}

	list, total, err := q.ListPolicyCompliance(ctx, pol.ID, "", store.Page{}, store.Unscoped)
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("list: %v total=%d %+v", err, total, list)
	}
	// Ordered by lower(hostname): alpha before zeta.
	if list[0].Hostname != "alpha" || list[1].Hostname != "zeta" {
		t.Fatalf("order: %+v", list)
	}

	filtered, total, err := q.ListPolicyCompliance(ctx, pol.ID, store.ComplianceNonCompliant, store.Page{}, store.Unscoped)
	if err != nil || total != 1 || len(filtered) != 1 || filtered[0].Hostname != "zeta" {
		t.Fatalf("filtered: %v total=%d %+v", err, total, filtered)
	}
}

func TestComplianceOverall(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	polA := newPolicy(t, q, "A")
	polB := newPolicy(t, q, "B")
	now := time.Now().UTC()

	compliantDev := newDevice(t, q, "compliant")
	nonCompliantDev := newDevice(t, q, "non-compliant")
	unknownDev := newDevice(t, q, "unknown")
	notEvaluatedDev := newDevice(t, q, "not-evaluated")

	for _, dc := range []store.DeviceCompliance{
		{DeviceID: compliantDev.ID, PolicyID: polA.ID, State: store.ComplianceCompliant, Failures: json.RawMessage(`[]`), EvaluatedAt: now},
		{DeviceID: nonCompliantDev.ID, PolicyID: polA.ID, State: store.ComplianceCompliant, Failures: json.RawMessage(`[]`), EvaluatedAt: now},
		{DeviceID: nonCompliantDev.ID, PolicyID: polB.ID, State: store.ComplianceNonCompliant, Failures: json.RawMessage(`[]`), EvaluatedAt: now},
		{DeviceID: unknownDev.ID, PolicyID: polA.ID, State: store.ComplianceUnknown, Failures: json.RawMessage(`[]`), EvaluatedAt: now},
	} {
		if err := q.UpsertDeviceCompliance(ctx, dc); err != nil {
			t.Fatal(err)
		}
	}

	got, err := q.ComplianceOverall(ctx, []uuid.UUID{compliantDev.ID, nonCompliantDev.ID, unknownDev.ID, notEvaluatedDev.ID})
	if err != nil {
		t.Fatal(err)
	}
	want := map[uuid.UUID]string{
		compliantDev.ID:    store.ComplianceCompliant,
		nonCompliantDev.ID: store.ComplianceNonCompliant,
		unknownDev.ID:      store.ComplianceUnknown,
		notEvaluatedDev.ID: store.ComplianceNotEvaluated,
	}
	for id, wantState := range want {
		if got[id] != wantState {
			t.Errorf("device %s: got %s, want %s", id, got[id], wantState)
		}
	}
}

func TestComplianceCounts(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	pol := newPolicy(t, q, "P")
	now := time.Now().UTC()

	compliantDev := newDevice(t, q, "compliant")
	nonCompliantDev := newDevice(t, q, "non-compliant")
	newDevice(t, q, "not-evaluated") // no compliance row at all

	retired := newDevice(t, q, "retired")
	if err := q.SetDeviceStatus(ctx, store.DefaultTenantID, retired.ID, store.DeviceRetired); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{DeviceID: retired.ID, PolicyID: pol.ID, State: store.ComplianceNonCompliant, Failures: json.RawMessage(`[]`), EvaluatedAt: now}); err != nil {
		t.Fatal(err)
	}

	if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{DeviceID: compliantDev.ID, PolicyID: pol.ID, State: store.ComplianceCompliant, Failures: json.RawMessage(`[]`), EvaluatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{DeviceID: nonCompliantDev.ID, PolicyID: pol.ID, State: store.ComplianceNonCompliant, Failures: json.RawMessage(`[]`), EvaluatedAt: now}); err != nil {
		t.Fatal(err)
	}

	counts, err := q.ComplianceCounts(ctx, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	// The retired device must not be counted even though it has a
	// non_compliant row: only active devices count.
	if counts[store.ComplianceCompliant] != 1 || counts[store.ComplianceNonCompliant] != 1 || counts[store.ComplianceNotEvaluated] != 1 {
		t.Fatalf("counts = %+v", counts)
	}
}

func TestPolicyStateCounts(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	q := st.Q()
	now := time.Now().UTC()

	scored := newPolicy(t, q, "Scored")
	empty := newPolicy(t, q, "Empty") // never evaluated

	devA := newDevice(t, q, "a")
	devB := newDevice(t, q, "b")
	devC := newDevice(t, q, "c")
	for _, dc := range []store.DeviceCompliance{
		{DeviceID: devA.ID, PolicyID: scored.ID, State: store.ComplianceCompliant, Failures: json.RawMessage(`[]`), EvaluatedAt: now},
		{DeviceID: devB.ID, PolicyID: scored.ID, State: store.ComplianceCompliant, Failures: json.RawMessage(`[]`), EvaluatedAt: now},
		{DeviceID: devC.ID, PolicyID: scored.ID, State: store.ComplianceNonCompliant, Failures: json.RawMessage(`[]`), EvaluatedAt: now},
	} {
		if err := q.UpsertDeviceCompliance(ctx, dc); err != nil {
			t.Fatal(err)
		}
	}

	counts, err := q.PolicyStateCounts(ctx, []uuid.UUID{scored.ID, empty.ID}, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{store.ComplianceCompliant: 2, store.ComplianceNonCompliant: 1, store.ComplianceUnknown: 0}
	for state, n := range want {
		if counts[scored.ID][state] != n {
			t.Errorf("scored[%s] = %d, want %d (%+v)", state, counts[scored.ID][state], n, counts[scored.ID])
		}
	}
	// A policy nothing has scored yet comes back present with all zeroes,
	// not absent from the map, so a caller never has to special-case it.
	for _, state := range []string{store.ComplianceCompliant, store.ComplianceNonCompliant, store.ComplianceUnknown} {
		if n, ok := counts[empty.ID][state]; !ok || n != 0 {
			t.Errorf("empty[%s] = %d, ok=%v, want 0, true", state, n, ok)
		}
	}

	// An id from another tenant's policy (or any id not among the caller's
	// own) is scoped out by the tenant filter, the same as every other
	// compliance query, and never picks up a stray row.
	other := uuid.Must(uuid.NewV7())
	otherCounts, err := q.PolicyStateCounts(ctx, []uuid.UUID{other}, store.Unscoped)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{store.ComplianceCompliant, store.ComplianceNonCompliant, store.ComplianceUnknown} {
		if otherCounts[other][state] != 0 {
			t.Errorf("other[%s] = %d, want 0", state, otherCounts[other][state])
		}
	}

	if empty, err := q.PolicyStateCounts(ctx, nil, store.Unscoped); err != nil || len(empty) != 0 {
		t.Errorf("nil ids: %v %+v", err, empty)
	}
}
