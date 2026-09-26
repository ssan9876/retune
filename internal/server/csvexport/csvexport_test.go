package csvexport_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/server/csvexport"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

func TestRowSanitizesEveryCell(t *testing.T) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := csvexport.Row(w, "PC-1", "=cmd", "+1", "-1", "@x", "\tt", "\rr", "a=b", ""); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	got, err := csv.NewReader(&buf).Read()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PC-1", "'=cmd", "'+1", "'-1", "'@x", "'\tt", "'\rr", "a=b", ""}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("row = %q, want %q", got, want)
	}
}

func TestTime(t *testing.T) {
	if got := csvexport.Time(nil); got != "" {
		t.Errorf("nil = %q", got)
	}
	at := time.Date(2026, 9, 1, 14, 30, 0, 0, time.FixedZone("PDT", -7*3600))
	if got := csvexport.Time(&at); got != "2026-09-01T21:30:00Z" {
		t.Errorf("a time in another zone = %q, want it in UTC", got)
	}
}

// deviceCount spans several export pages, so the paging is exercised.
const deviceCount = 2*store.MaxPageLimit + 50

// TestExportsPageThroughEveryRow: a fleet larger than one page comes out
// whole, each device exactly once - including when every device has the
// same hostname and enrolment time, which is where an ordering that isn't
// total lets one page repeat rows another page then misses.
func TestExportsPageThroughEveryRow(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	q := st.Q()
	now := time.Now().UTC().Truncate(time.Microsecond)

	policy := store.CompliancePolicy{
		ID: uuid.Must(uuid.NewV7()), Name: "Baseline", Rules: []byte(`[]`),
		CreatedAt: now, UpdatedAt: now, CreatedBy: "test",
	}
	if err := q.CreateCompliancePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	for i := range deviceCount {
		d := store.Device{
			ID: uuid.Must(uuid.NewV7()), Hostname: "PC-SAME", Serial: fmt.Sprintf("SN-%04d", i),
			Status: store.DeviceActive, CertSerial: "c", CertExpiresAt: now.Add(time.Hour), EnrolledAt: now,
		}
		if err := q.CreateDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		// Every other device fails, with a detail naming it.
		state, failures := store.ComplianceCompliant, `[]`
		if i%2 == 1 {
			state = store.ComplianceNonCompliant
			failures = fmt.Sprintf(`[{"rule":"r","state":"non_compliant","detail":"SN-%04d a"},{"rule":"r","state":"non_compliant","detail":"b"}]`, i)
		}
		if err := q.UpsertDeviceCompliance(ctx, store.DeviceCompliance{
			DeviceID: d.ID, PolicyID: policy.ID, State: state, Failures: []byte(failures), EvaluatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	var devices bytes.Buffer
	if err := csvexport.WriteDevices(ctx, q, store.Unscoped, &devices); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&devices).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rows[0], ",") != strings.Join(csvexport.DevicesHeader, ",") {
		t.Fatalf("header = %v", rows[0])
	}
	seen := map[string]int{}
	for _, r := range rows[1:] {
		seen[r[1]]++ // serial
		wantState := store.ComplianceCompliant
		var n int
		fmt.Sscanf(r[1], "SN-%d", &n)
		if n%2 == 1 {
			wantState = store.ComplianceNonCompliant
		}
		if r[8] != wantState {
			t.Fatalf("%s: compliance %q, want %q", r[1], r[8], wantState)
		}
	}
	checkEachOnce(t, "device export", seen, len(rows)-1)

	var policyRows bytes.Buffer
	if err := csvexport.WritePolicyDevices(ctx, q, policy.ID, "", store.Unscoped, &policyRows); err != nil {
		t.Fatal(err)
	}
	rows, err = csv.NewReader(&policyRows).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rows[0], ",") != strings.Join(csvexport.PolicyDevicesHeader, ",") {
		t.Fatalf("header = %v", rows[0])
	}
	// Only the failing devices name themselves, so count those, and every
	// passing one by state.
	seen = map[string]int{}
	passing := 0
	for _, r := range rows[1:] {
		switch r[1] {
		case store.ComplianceCompliant:
			passing++
			if r[2] != "" {
				t.Fatalf("a passing row has failures: %v", r)
			}
		case store.ComplianceNonCompliant:
			serial, rest, _ := strings.Cut(r[2], " ")
			if rest != "a; b" {
				t.Fatalf("failures cell = %q, want the details joined", r[2])
			}
			seen[serial]++
		default:
			t.Fatalf("row %v", r)
		}
	}
	if passing != deviceCount/2 || len(rows)-1 != deviceCount {
		t.Errorf("policy export: %d rows, %d passing, want %d and %d", len(rows)-1, passing, deviceCount, deviceCount/2)
	}
	for i := 1; i < deviceCount; i += 2 {
		if n := seen[fmt.Sprintf("SN-%04d", i)]; n != 1 {
			t.Errorf("policy export: SN-%04d appears %d times", i, n)
		}
	}

	// Only one state, when asked.
	policyRows.Reset()
	if err := csvexport.WritePolicyDevices(ctx, q, policy.ID, store.ComplianceNonCompliant, store.Unscoped, &policyRows); err != nil {
		t.Fatal(err)
	}
	rows, _ = csv.NewReader(&policyRows).ReadAll()
	if len(rows)-1 != deviceCount/2 {
		t.Errorf("non-compliant only: %d rows, want %d", len(rows)-1, deviceCount/2)
	}
}

func checkEachOnce(t *testing.T, what string, seen map[string]int, rows int) {
	t.Helper()
	for i := range deviceCount {
		if n := seen[fmt.Sprintf("SN-%04d", i)]; n != 1 {
			t.Errorf("%s: SN-%04d appears %d times", what, i, n)
		}
	}
	if rows != deviceCount {
		t.Errorf("%s: %d rows, want %d", what, rows, deviceCount)
	}
}
