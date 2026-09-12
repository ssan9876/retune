package executor

import (
	"bytes"
	"strings"
)

// capped collects up to limit bytes and remembers whether more arrived.
type capped struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func newCapped(limit int) *capped { return &capped{limit: limit} }

func (c *capped) Write(p []byte) (int, error) {
	room := c.limit - c.buf.Len()
	switch {
	case room <= 0:
		if len(p) > 0 {
			c.truncated = true
		}
	case len(p) > room:
		c.buf.Write(p[:room])
		c.truncated = true
	default:
		c.buf.Write(p)
	}
	return len(p), nil
}

// String returns the captured text with invalid UTF-8 repaired, so it is safe
// to put in JSON and in Postgres.
func (c *capped) String() string {
	return strings.ToValidUTF8(strings.ReplaceAll(c.buf.String(), "\x00", ""), "�")
}

func (c *capped) Truncated() bool { return c.truncated }
