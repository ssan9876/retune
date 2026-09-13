package session

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"retune/internal/protocol"
)

// A syncer that runs on empty is started with nothing assigned; one that does
// not is left alone. That difference is the whole reason profiles can revert:
// an empty list is exactly when an unassigned profile must be undone.
func TestDispatchHonoursTheEmptyRule(t *testing.T) {
	cases := map[string]struct {
		items     []protocol.Item
		wantEager int
		wantLazy  int
	}{
		"nothing assigned": {
			items: nil, wantEager: 1, wantLazy: 0,
		},
		"something assigned": {
			items:     []protocol.Item{{Kind: "script", ID: "s1", Version: 1}},
			wantEager: 1, wantLazy: 1,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			eager := &countingSyncer{name: "eager", onEmpty: true}
			lazy := &countingSyncer{name: "lazy"}
			var pending sync.WaitGroup

			dispatch(context.Background(), []ItemSyncer{eager, lazy}, tc.items,
				&pending, slog.New(slog.DiscardHandler))
			pending.Wait()

			if eager.calls() != tc.wantEager {
				t.Errorf("eager syncer ran %d times, want %d", eager.calls(), tc.wantEager)
			}
			if lazy.calls() != tc.wantLazy {
				t.Errorf("lazy syncer ran %d times, want %d", lazy.calls(), tc.wantLazy)
			}
		})
	}
}

// Every syncer gets the same item list, and one that fails does not stop the
// others: a broken deployment must not hold up the rest of a check-in.
func TestDispatchIsolatesFailures(t *testing.T) {
	angry := &countingSyncer{name: "angry", err: errors.New("no")}
	calm := &countingSyncer{name: "calm"}
	var pending sync.WaitGroup

	items := []protocol.Item{{Kind: "script", ID: "s1", Version: 1}}
	dispatch(context.Background(), []ItemSyncer{angry, calm}, items,
		&pending, slog.New(slog.DiscardHandler))
	pending.Wait()

	if calm.calls() != 1 {
		t.Errorf("a failing syncer must not stop the next one, got %d", calm.calls())
	}
	if got := angry.sawItems(); len(got) != 1 {
		t.Errorf("every syncer gets the whole list, got %+v", got)
	}
}

// countingSyncer records how often it ran and what it was given.
type countingSyncer struct {
	name    string
	onEmpty bool
	err     error

	mu    sync.Mutex
	n     int
	items []protocol.Item
}

func (c *countingSyncer) Sync(_ context.Context, items []protocol.Item) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	c.items = items
	return c.err
}
func (c *countingSyncer) RunOnEmpty() bool { return c.onEmpty }
func (c *countingSyncer) Name() string     { return c.name }
func (c *countingSyncer) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
func (c *countingSyncer) sawItems() []protocol.Item {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.items
}
