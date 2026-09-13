package executor

import (
	"bytes"
	"strings"
)

// Capped collects up to limit bytes and remembers whether more arrived, so
// output can be bounded without losing the fact that it was cut.
type Capped struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

// NewCapped returns a writer that keeps at most limit bytes.
func NewCapped(limit int) *Capped { return &Capped{limit: limit} }

func (c *Capped) Write(p []byte) (int, error) {
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
func (c *Capped) String() string {
	return strings.ToValidUTF8(strings.ReplaceAll(c.buf.String(), "\x00", ""), "�")
}

func (c *Capped) Truncated() bool { return c.truncated }
