package wake

import (
	"context"
	"testing"
	"time"
)

func TestHub(t *testing.T) {
	h := NewHub()
	done := make(chan bool)
	go func() { done <- h.Wait(context.Background(), "device:1", 5*time.Second, nil) }()
	// Notify until the waiter has registered and been woken.
	deadline := time.After(3 * time.Second)
	for woken := false; !woken; {
		h.Notify("device:1")
		select {
		case woke := <-done:
			if !woke {
				t.Fatal("a notified wait must report true")
			}
			woken = true
		case <-deadline:
			t.Fatal("the wait was never woken")
		case <-time.After(10 * time.Millisecond):
		}
	}
	start := time.Now()
	if h.Wait(context.Background(), "device:2", 50*time.Millisecond, nil) || time.Since(start) < 50*time.Millisecond {
		t.Fatal("an un-notified wait times out, false")
	}
	if !h.Wait(context.Background(), "device:3", time.Hour, func() bool { return true }) {
		t.Fatal("something already there answers at once")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h.Wait(ctx, "device:4", time.Hour, nil) {
		t.Fatal("a cancelled wait is false")
	}
	h.mu.Lock()
	n := len(h.waiters)
	h.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d keys left waiting", n)
	}
}
