package policy_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"retune/internal/agent/policy"
	"retune/internal/protocol"
)

// fakeStore is an in-memory Store.
type fakeStore struct {
	prior   map[string][]byte
	records map[string]policy.Record
}

func newStore() *fakeStore {
	return &fakeStore{prior: map[string][]byte{}, records: map[string]policy.Record{}}
}

func (s *fakeStore) PriorState(id string) ([]byte, bool, error) {
	raw, ok := s.prior[id]
	return raw, ok, nil
}
func (s *fakeStore) SetPriorState(id string, raw []byte) error { s.prior[id] = raw; return nil }
func (s *fakeStore) DeletePriorState(id string) error          { delete(s.prior, id); return nil }
func (s *fakeStore) ProfileRecords() (map[string]policy.Record, error) {
	out := map[string]policy.Record{}
	for k, v := range s.records {
		out[k] = v
	}
	return out, nil
}
func (s *fakeStore) SetProfileRecord(id string, rec policy.Record) error {
	s.records[id] = rec
	return nil
}
func (s *fakeStore) DeleteProfileRecord(id string) error { delete(s.records, id); return nil }

// fakeHandler is a settable, testable stand-in for a real setting handler.
type fakeHandler struct {
	kind string
	// current is what the machine looks like, keyed by identity.
	current map[string]string
	// want is what Test compares against; a setting is compliant when the
	// machine's value equals the setting's data.
	calls    []string
	setErr   error
	testErr  error
	panicOn  string
	reverted map[string]policy.State
}

func newHandler(kind string) *fakeHandler {
	return &fakeHandler{kind: kind, current: map[string]string{}, reverted: map[string]policy.State{}}
}

func (h *fakeHandler) Kind() string { return h.kind }

func (h *fakeHandler) Get(_ context.Context, s protocol.Setting) (policy.State, error) {
	h.calls = append(h.calls, "get:"+s.Identity())
	value, ok := h.current[s.Identity()]
	if !ok {
		return policy.State{}, nil
	}
	raw, _ := json.Marshal(value)
	return policy.State{Exists: true, Data: raw}, nil
}

func (h *fakeHandler) Test(_ context.Context, s protocol.Setting) (bool, error) {
	h.calls = append(h.calls, "test:"+s.Identity())
	if h.panicOn == s.Identity() {
		panic("handler exploded")
	}
	if h.testErr != nil {
		return false, h.testErr
	}
	return h.current[s.Identity()] == s.Data, nil
}

func (h *fakeHandler) Set(_ context.Context, s protocol.Setting) error {
	h.calls = append(h.calls, "set:"+s.Identity())
	if h.setErr != nil {
		return h.setErr
	}
	h.current[s.Identity()] = s.Data
	return nil
}

func (h *fakeHandler) Revert(_ context.Context, s protocol.Setting, prior policy.State) error {
	h.calls = append(h.calls, "revert:"+s.Identity())
	h.reverted[s.Identity()] = prior
	if !prior.Exists {
		delete(h.current, s.Identity())
		return nil
	}
	var value string
	if err := json.Unmarshal(prior.Data, &value); err != nil {
		return err
	}
	h.current[s.Identity()] = value
	return nil
}

// fakeReporter captures what was sent to the server.
type fakeReporter struct {
	reports map[string]protocol.ProfileStatus
	err     error
}

func newReporter() *fakeReporter {
	return &fakeReporter{reports: map[string]protocol.ProfileStatus{}}
}

func (r *fakeReporter) ReportProfileStatus(_ context.Context, id string, st protocol.ProfileStatus) error {
	r.reports[id] = st
	return r.err
}

// reg builds a registry setting whose Data is what the fake handler compares.
func reg(name, data string) protocol.Setting {
	return protocol.Setting{
		Kind: protocol.KindRegistry, Hive: "HKLM", Key: "SOFTWARE/Retune",
		Name: name, Type: protocol.RegSZ, Data: data,
	}
}

func statusOf(t *testing.T, report protocol.ProfileStatus, identity string) protocol.SettingResult {
	t.Helper()
	for _, r := range report.Settings {
		if r.Identity == identity {
			return r
		}
	}
	t.Fatalf("no result for %s in %+v", identity, report.Settings)
	return protocol.SettingResult{}
}

func newReconciler(h policy.Handler, st *fakeStore, rep *fakeReporter) *policy.Reconciler {
	return &policy.Reconciler{Handlers: []policy.Handler{h}, State: st, Client: rep}
}

func TestCompliantSettingIsNotSet(t *testing.T) {
	h := newHandler(protocol.KindRegistry)
	h.current[reg("A", "yes").Identity()] = "yes"
	st, rep := newStore(), newReporter()
	r := newReconciler(h, st, rep)

	err := r.Reconcile(context.Background(), []policy.Assigned{
		{ProfileID: "p1", Version: 1, Settings: []protocol.Setting{reg("A", "yes")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := statusOf(t, rep.reports["p1"], reg("A", "yes").Identity())
	if result.Status != protocol.SettingCompliant {
		t.Fatalf("status = %q, want compliant", result.Status)
	}
	for _, call := range h.calls {
		if strings.HasPrefix(call, "set:") {
			t.Fatalf("a compliant setting must not be set again, calls: %v", h.calls)
		}
	}
}

func TestDriftIsRemediatedAndRetested(t *testing.T) {
	h := newHandler(protocol.KindRegistry)
	h.current[reg("A", "yes").Identity()] = "no"
	st, rep := newStore(), newReporter()
	r := newReconciler(h, st, rep)

	if err := r.Reconcile(context.Background(), []policy.Assigned{
		{ProfileID: "p1", Version: 1, Settings: []protocol.Setting{reg("A", "yes")}},
	}); err != nil {
		t.Fatal(err)
	}
	result := statusOf(t, rep.reports["p1"], reg("A", "yes").Identity())
	if result.Status != protocol.SettingRemediated {
		t.Fatalf("status = %q, want remediated", result.Status)
	}
	// Test, set, then test again: the second test is what proves it worked.
	want := []string{"test:", "get:", "set:", "test:"}
	if len(h.calls) != len(want) {
		t.Fatalf("calls = %v, want a test, a get, a set and a second test", h.calls)
	}
	for i, prefix := range want {
		if !strings.HasPrefix(h.calls[i], prefix) {
			t.Fatalf("call %d = %q, want %q", i, h.calls[i], prefix)
		}
	}
}

func TestASettingThatDoesNotStickIsAnError(t *testing.T) {
	h := newHandler(protocol.KindRegistry)
	h.setErr = nil
	// Set succeeds but the machine never matches: Set writes nothing here.
	h.current[reg("A", "yes").Identity()] = "no"
	st, rep := newStore(), newReporter()
	r := newReconciler(&stubbornHandler{fakeHandler: h}, st, rep)

	if err := r.Reconcile(context.Background(), []policy.Assigned{
		{ProfileID: "p1", Version: 1, Settings: []protocol.Setting{reg("A", "yes")}},
	}); err != nil {
		t.Fatal(err)
	}
	result := statusOf(t, rep.reports["p1"], reg("A", "yes").Identity())
	if result.Status != protocol.SettingError {
		t.Fatalf("status = %q, want error", result.Status)
	}
	if !strings.Contains(result.Detail, "still does not match") {
		t.Errorf("detail = %q", result.Detail)
	}
}

// stubbornHandler accepts a Set but never actually changes anything.
type stubbornHandler struct{ *fakeHandler }

func (h *stubbornHandler) Set(_ context.Context, s protocol.Setting) error {
	h.calls = append(h.calls, "set:"+s.Identity())
	return nil
}

func TestFailuresAreReportedPerSetting(t *testing.T) {
	h := newHandler(protocol.KindRegistry)
	h.setErr = errors.New("access denied")
	st, rep := newStore(), newReporter()
	r := newReconciler(h, st, rep)

	if err := r.Reconcile(context.Background(), []policy.Assigned{
		{ProfileID: "p1", Version: 1, Settings: []protocol.Setting{reg("A", "yes"), reg("B", "yes")}},
	}); err != nil {
		t.Fatal(err)
	}
	report := rep.reports["p1"]
	if len(report.Settings) != 2 {
		t.Fatalf("both settings should be reported, got %+v", report.Settings)
	}
	for _, result := range report.Settings {
		if result.Status != protocol.SettingError || result.Detail != "access denied" {
			t.Fatalf("result = %+v", result)
		}
	}
}

func TestAPanickingHandlerIsContained(t *testing.T) {
	h := newHandler(protocol.KindRegistry)
	h.panicOn = reg("A", "yes").Identity()
	st, rep := newStore(), newReporter()
	r := newReconciler(h, st, rep)

	if err := r.Reconcile(context.Background(), []policy.Assigned{
		{ProfileID: "p1", Version: 1, Settings: []protocol.Setting{reg("A", "yes"), reg("B", "yes")}},
	}); err != nil {
		t.Fatal(err)
	}
	report := rep.reports["p1"]
	if len(report.Settings) != 2 {
		t.Fatalf("the other setting should still be reported, got %+v", report.Settings)
	}
	bad := statusOf(t, report, reg("A", "yes").Identity())
	if bad.Status != protocol.SettingError || !strings.Contains(bad.Detail, "panicked") {
		t.Fatalf("result = %+v", bad)
	}
	good := statusOf(t, report, reg("B", "yes").Identity())
	if good.Status != protocol.SettingRemediated {
		t.Fatalf("the second setting should still have been applied, got %+v", good)
	}
}

func TestUnknownKindIsAnError(t *testing.T) {
	st, rep := newStore(), newReporter()
	r := &policy.Reconciler{State: st, Client: rep} // no handlers at all

	if err := r.Reconcile(context.Background(), []policy.Assigned{
		{ProfileID: "p1", Version: 1, Settings: []protocol.Setting{reg("A", "yes")}},
	}); err != nil {
		t.Fatal(err)
	}
	result := statusOf(t, rep.reports["p1"], reg("A", "yes").Identity())
	if result.Status != protocol.SettingError || !strings.Contains(result.Detail, "cannot apply") {
		t.Fatalf("result = %+v", result)
	}
}

// Two profiles disagreeing about one setting apply neither and both hear about
// it, because picking a winner would make the machine depend on assignment
// order.
func TestConflictingProfilesApplyNeither(t *testing.T) {
	h := newHandler(protocol.KindRegistry)
	st, rep := newStore(), newReporter()
	r := newReconciler(h, st, rep)

	err := r.Reconcile(context.Background(), []policy.Assigned{
		{ProfileID: "p1", Version: 1, Settings: []protocol.Setting{reg("A", "yes")}},
		{ProfileID: "p2", Version: 1, Settings: []protocol.Setting{reg("A", "no")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"p1", "p2"} {
		result := statusOf(t, rep.reports[id], reg("A", "yes").Identity())
		if result.Status != protocol.SettingConflict {
			t.Fatalf("%s: status = %q, want conflict", id, result.Status)
		}
		if !strings.Contains(result.Detail, "p1") || !strings.Contains(result.Detail, "p2") {
			t.Errorf("%s: detail should name both profiles, got %q", id, result.Detail)
		}
	}
	for _, call := range h.calls {
		if strings.HasPrefix(call, "set:") {
			t.Fatalf("a conflicting setting must not be applied, calls: %v", h.calls)
		}
	}
}

// Two profiles asking for exactly the same thing is not a conflict.
func TestIdenticalSettingsAreNotAConflict(t *testing.T) {
	h := newHandler(protocol.KindRegistry)
	st, rep := newStore(), newReporter()
	r := newReconciler(h, st, rep)

	err := r.Reconcile(context.Background(), []policy.Assigned{
		{ProfileID: "p1", Version: 1, Settings: []protocol.Setting{reg("A", "yes")}},
		{ProfileID: "p2", Version: 1, Settings: []protocol.Setting{reg("A", "yes")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"p1", "p2"} {
		result := statusOf(t, rep.reports[id], reg("A", "yes").Identity())
		if result.Status != protocol.SettingRemediated {
			t.Fatalf("%s: status = %q, want remediated", id, result.Status)
		}
	}
	// Applied once, not twice.
	sets := 0
	for _, call := range h.calls {
		if strings.HasPrefix(call, "set:") {
			sets++
		}
	}
	if sets != 1 {
		t.Fatalf("the setting should be applied once, got %d", sets)
	}
}

func TestRevertRestoresWhatWasThereBefore(t *testing.T) {
	h := newHandler(protocol.KindRegistry)
	identity := reg("A", "managed").Identity()
	h.current[identity] = "original"
	st, rep := newStore(), newReporter()
	r := newReconciler(h, st, rep)
	ctx := context.Background()

	assigned := []policy.Assigned{{
		ProfileID: "p1", Version: 1,
		Settings: []protocol.Setting{reg("A", "managed")},
		Options:  protocol.ProfileOptions{RevertOnRemoval: true},
	}}
	if err := r.Reconcile(ctx, assigned); err != nil {
		t.Fatal(err)
	}
	if h.current[identity] != "managed" {
		t.Fatalf("the setting should have been applied, got %q", h.current[identity])
	}

	// Apply again: the prior state must not be overwritten with what Retune
	// itself wrote.
	h.current[identity] = "drifted"
	if err := r.Reconcile(ctx, assigned); err != nil {
		t.Fatal(err)
	}

	// The profile stops applying.
	if err := r.Reconcile(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if h.current[identity] != "original" {
		t.Fatalf("revert restored %q, want the original value", h.current[identity])
	}
	if _, found, _ := st.PriorState(identity); found {
		t.Error("the recorded previous state should be forgotten after a revert")
	}
}

func TestNoRevertWhenTheOptionIsOff(t *testing.T) {
	h := newHandler(protocol.KindRegistry)
	identity := reg("A", "managed").Identity()
	h.current[identity] = "original"
	st, rep := newStore(), newReporter()
	r := newReconciler(h, st, rep)
	ctx := context.Background()

	if err := r.Reconcile(ctx, []policy.Assigned{{
		ProfileID: "p1", Version: 1, Settings: []protocol.Setting{reg("A", "managed")},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Reconcile(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if h.current[identity] != "managed" {
		t.Fatalf("without revert_on_removal the setting should stay, got %q", h.current[identity])
	}
}

// A setting another profile still wants is left alone when one profile is
// removed.
func TestRevertLeavesSettingsAnotherProfileStillWants(t *testing.T) {
	h := newHandler(protocol.KindRegistry)
	identity := reg("A", "managed").Identity()
	h.current[identity] = "original"
	st, rep := newStore(), newReporter()
	r := newReconciler(h, st, rep)
	ctx := context.Background()

	both := []policy.Assigned{
		{ProfileID: "p1", Version: 1, Settings: []protocol.Setting{reg("A", "managed")},
			Options: protocol.ProfileOptions{RevertOnRemoval: true}},
		{ProfileID: "p2", Version: 1, Settings: []protocol.Setting{reg("A", "managed")}},
	}
	if err := r.Reconcile(ctx, both); err != nil {
		t.Fatal(err)
	}

	// p1 goes away; p2 still wants the same setting.
	if err := r.Reconcile(ctx, both[1:]); err != nil {
		t.Fatal(err)
	}
	if h.current[identity] != "managed" {
		t.Fatalf("the setting is still wanted, so it should stay, got %q", h.current[identity])
	}
}

func TestReportingFailureIsReturned(t *testing.T) {
	h := newHandler(protocol.KindRegistry)
	st, rep := newStore(), newReporter()
	rep.err = errors.New("server unreachable")
	r := newReconciler(h, st, rep)

	err := r.Reconcile(context.Background(), []policy.Assigned{
		{ProfileID: "p1", Version: 1, Settings: []protocol.Setting{reg("A", "yes")}},
	})
	if err == nil {
		t.Fatal("a failure to report should be returned so the caller can log it")
	}
	// The work was still done.
	if h.current[reg("A", "yes").Identity()] != "yes" {
		t.Error("the setting should have been applied even though reporting failed")
	}
}
