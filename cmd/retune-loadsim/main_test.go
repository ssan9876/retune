package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPercentile(t *testing.T) {
	var lat []time.Duration
	for i := 1; i <= 100; i++ {
		lat = append(lat, time.Duration(i)*time.Millisecond)
	}
	if got := percentile(lat, 0.50); got != 50*time.Millisecond {
		t.Errorf("p50 = %s", got)
	}
	if got := percentile(lat, 0.99); got != 99*time.Millisecond {
		t.Errorf("p99 = %s", got)
	}
	if got := percentile(nil, 0.5); got != 0 {
		t.Errorf("empty = %s", got)
	}
}

func TestReport(t *testing.T) {
	st := newStats()
	st.record("checkin", 10*time.Millisecond, nil)
	st.record("checkin", 20*time.Millisecond, nil)
	st.record("checkin", 0, errors.New("POST /checkin: 503"))
	var out bytes.Buffer
	st.report(&out, 2*time.Second)
	text := out.String()
	if !strings.Contains(text, "checkin") || !strings.Contains(text, "1.0") || !strings.Contains(text, "last checkin error: POST /checkin: 503") {
		t.Fatalf("report:\n%s", text)
	}
}

// The simulated inventory is about the size of a real one, and the same for
// the same device, so the server sees it unchanged after the first upload.
func TestInventory(t *testing.T) {
	a, err := json.Marshal(inventory("LOADSIM-1", 1, 150))
	if err != nil {
		t.Fatal(err)
	}
	if len(a) < 10<<10 || len(a) > 100<<10 {
		t.Errorf("inventory is %d bytes", len(a))
	}
	first := inventory("LOADSIM-1", 1, 150)
	second := inventory("LOADSIM-1", 1, 150)
	first.CollectedAt, second.CollectedAt = time.Time{}, time.Time{}
	x, _ := json.Marshal(first)
	y, _ := json.Marshal(second)
	if !bytes.Equal(x, y) {
		t.Error("the same device's inventory differs between calls")
	}
}
