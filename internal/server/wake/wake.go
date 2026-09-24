// Package wake lets a request wait for something to arrive - a command for
// a device, input for a remote session - and wakes it the moment it does,
// on whichever server holds it.
package wake

import (
	"context"
	"sync"
	"time"

	"retune/internal/server/store"
)

// Hub holds the requests waiting on each key.
type Hub struct {
	mu      sync.Mutex
	waiters map[string]map[chan struct{}]struct{}
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{waiters: map[string]map[chan struct{}]struct{}{}} }

// Run feeds the hub from the database's notifications until ctx ends.
func (h *Hub) Run(ctx context.Context, st *store.Store) {
	st.Listen(ctx, store.WakeChannel, h.Notify)
}

// Notify wakes everything waiting on key.
func (h *Hub) Notify(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.waiters[key] {
		close(ch)
	}
	delete(h.waiters, key)
}

// Wait returns true when key is notified, or false once timeout passes or
// ctx ends. ready, checked after registering, says whether what the caller
// waits for is already there, so a notification sent between the caller's
// own check and this wait isn't missed.
func (h *Hub) Wait(ctx context.Context, key string, timeout time.Duration, ready func() bool) bool {
	ch := make(chan struct{})
	h.mu.Lock()
	if h.waiters[key] == nil {
		h.waiters[key] = map[chan struct{}]struct{}{}
	}
	h.waiters[key][ch] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		if set := h.waiters[key]; set != nil {
			delete(set, ch)
			if len(set) == 0 {
				delete(h.waiters, key)
			}
		}
		h.mu.Unlock()
	}()
	if ready != nil && ready() {
		return true
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ch:
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// Keys a hub is woken on.
func DeviceKey(deviceID string) string   { return "device:" + deviceID }
func SessionKey(sessionID string) string { return "session:" + sessionID }
