package app_test

import (
	"net/http"
	"testing"
	"time"

	"retune/internal/server/store"
)

// TestCommandsWakeWaitingDevices: a device waiting between check-ins hears
// about a command in seconds, through the database's notifications.
func TestCommandsWakeWaitingDevices(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	id, agent := enrollDevice(t, a, srv, "PC-WAITING")
	wait := func(seconds string) (int, time.Duration) {
		start := time.Now()
		status, _ := send(t, agent, http.MethodGet, srv.URL+"/api/agent/v1/wait?seconds="+seconds, nil)
		return status, time.Since(start)
	}

	// Nothing queued: the wait runs out.
	if status, took := wait("1"); status != http.StatusNoContent || took < time.Second {
		t.Fatalf("an empty wait: %d after %s", status, took)
	}

	// Queued while the device waits: it is woken at once.
	type result struct {
		status int
		took   time.Duration
	}
	done := make(chan result, 1)
	go func() {
		status, took := wait("30")
		done <- result{status, took}
	}()
	time.Sleep(500 * time.Millisecond) // let it start waiting
	if status, body := admin.do(http.MethodPost, "/commands", map[string]any{
		"device_ids": []string{id.String()}, "type": "refresh_inventory",
	}); status != http.StatusCreated {
		t.Fatalf("queue: %d %s", status, body)
	}
	select {
	case r := <-done:
		if r.status != http.StatusOK || r.took > 10*time.Second {
			t.Fatalf("woken: %d after %s", r.status, r.took)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the waiting device was never woken")
	}

	// Already queued: the wait answers at once.
	if status, took := wait("30"); status != http.StatusOK || took > 5*time.Second {
		t.Fatalf("already queued: %d after %s", status, took)
	}
}
