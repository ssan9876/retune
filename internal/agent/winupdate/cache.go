package winupdate

import (
	"context"
	"sync"
	"time"

	"retune/internal/protocol"
)

// Store keeps the last search, so a slow one isn't repeated with every
// inventory.
type Store interface {
	UpdateScan() (protocol.UpdateStatus, bool, error)
	SetUpdateScan(protocol.UpdateStatus) error
	ClearUpdateScan() error
}

// retryFailed is how soon a search that failed is tried again.
const retryFailed = time.Hour

// Cache answers with the last search while it is younger than MaxAge, and
// searches again when it isn't.
type Cache struct {
	Store  Store
	Runner Runner
	Now    func() time.Time
	MaxAge time.Duration

	mu sync.Mutex
}

func (c *Cache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Status is the device's update status: remembered, or searched for now.
func (c *Cache) Status(ctx context.Context) *protocol.UpdateStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if st, ok, err := c.Store.UpdateScan(); err == nil && ok {
		age := now.Sub(st.ScannedAt)
		if (st.Error == "" && age < c.MaxAge) || (st.Error != "" && age < retryFailed) {
			return &st
		}
	}
	st := Scan(ctx, c.Runner, now)
	// Remembered even when it failed, so a machine that can't reach Windows
	// Update isn't searched on every inventory.
	_ = c.Store.SetUpdateScan(st)
	return &st
}

// Invalidate forgets the last search, after updates were installed.
func (c *Cache) Invalidate() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Store.ClearUpdateScan()
}
