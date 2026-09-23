package sweeper

import (
	"sort"
	"sync"
	"time"
)

// Run outcomes, as the metrics endpoint labels them.
const (
	ResultOK      = "ok"
	ResultError   = "error"
	ResultSkipped = "skipped" // another replica held the advisory lock
)

// Stats keeps what each job has done in this process, for the metrics
// endpoint. It is per process on purpose: a counter that restarts at zero
// with the process is what Prometheus expects, and the question it answers -
// "is this replica's sweeper still running" - is about this process.
type Stats struct {
	mu   sync.Mutex
	jobs map[string]*JobStats
}

// JobStats is one job's record.
type JobStats struct {
	Runs        map[string]int64 // by result
	Rows        int64
	LastSuccess time.Time // zero until the job first succeeds
}

// NewStats returns an empty record.
func NewStats() *Stats { return &Stats{jobs: map[string]*JobStats{}} }

func (s *Stats) record(job string, rows int64, ran bool, err error, at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	js := s.jobs[job]
	if js == nil {
		js = &JobStats{Runs: map[string]int64{}}
		s.jobs[job] = js
	}
	switch {
	case err != nil:
		js.Runs[ResultError]++
	case !ran:
		js.Runs[ResultSkipped]++
	default:
		js.Runs[ResultOK]++
		js.Rows += rows
		js.LastSuccess = at
	}
}

// Snapshot copies the record, sorted by job name so output is stable.
func (s *Stats) Snapshot() []NamedJobStats {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]NamedJobStats, 0, len(s.jobs))
	for name, js := range s.jobs {
		runs := make(map[string]int64, len(js.Runs))
		for k, v := range js.Runs {
			runs[k] = v
		}
		out = append(out, NamedJobStats{Name: name, JobStats: JobStats{Runs: runs, Rows: js.Rows, LastSuccess: js.LastSuccess}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// NamedJobStats is one entry of a Snapshot.
type NamedJobStats struct {
	Name string
	JobStats
}
