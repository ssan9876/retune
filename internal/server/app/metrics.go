package app

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"retune/internal/server/adminapi"
	"retune/internal/server/store"
	"retune/internal/server/sweeper"
)

// metricsTimeout bounds one scrape's queries. A scraper times out on its own
// schedule; a scrape that outlives it is work nobody will read.
const metricsTimeout = 10 * time.Second

// mountMetrics adds GET /metrics, in the Prometheus text format, on the root
// mux beside the health probes: a scraper cannot hold a console session, so
// the endpoint lives outside the admin API and has a bearer token of its own.
// With no token configured it answers 404 rather than 401, a door that is
// not there rather than one that says it is locked. The route is registered
// either way: left unmounted, the console's catch-all would answer /metrics
// with the app shell and a 200.
func mountMetrics(mux *http.ServeMux, st *store.Store, token string, stats *sweeper.Stats, now func() time.Time, log *slog.Logger) {
	want := []byte("Bearer " + token)
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			http.NotFound(w, r)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			writePlain(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), metricsTimeout)
		defer cancel()
		body, err := renderMetrics(ctx, st.Q(), stats, now())
		if err != nil {
			// All or nothing: a partial page would read to Prometheus as
			// gauges that dropped to zero, which is a lie worth an alert.
			log.Error("metrics scrape failed", "err", err)
			writePlain(w, http.StatusInternalServerError, "metrics unavailable")
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	})
}

// The fixed label values each fleet series always carries, so a zero is a
// zero rather than a series that is missing until something happens.
var (
	deploymentKinds  = []string{"script", "app", "profile", "agent"}
	complianceStates = []string{store.ComplianceCompliant, store.ComplianceNonCompliant, store.ComplianceUnknown, store.ComplianceNotEvaluated}
	commandStatuses  = []string{"queued", "delivered", "running"}
	alertKinds       = []string{"device_non_compliant", "device_stale", "deployment_failed"}
	runResults       = []string{sweeper.ResultOK, sweeper.ResultError, sweeper.ResultSkipped}
)

func renderMetrics(ctx context.Context, q *store.Queries, stats *sweeper.Stats, now time.Time) ([]byte, error) {
	var b bytes.Buffer

	active, stale, retired, err := q.DeviceBucketCounts(ctx, now.Add(-adminapi.StaleAfter))
	if err != nil {
		return nil, fmt.Errorf("device counts: %w", err)
	}
	family(&b, "retune_devices", "gauge", "Enrolled devices by state; stale means active but unseen for seven days.")
	sample(&b, "retune_devices", "state", "active", active)
	sample(&b, "retune_devices", "state", "stale", stale)
	sample(&b, "retune_devices", "state", "retired", retired)

	compliance, err := q.ComplianceCounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("compliance counts: %w", err)
	}
	family(&b, "retune_compliance_devices", "gauge", "Active devices by overall compliance state.")
	for _, s := range complianceStates {
		sample(&b, "retune_compliance_devices", "state", s, compliance[s])
	}

	failed, err := q.FailedDeploymentCounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed deployments: %w", err)
	}
	family(&b, "retune_failed_deployments", "gauge", "Active devices with at least one failed deployment, by item kind.")
	for _, k := range deploymentKinds {
		sample(&b, "retune_failed_deployments", "kind", k, failed[k])
	}

	outstanding, err := q.OutstandingCommandCounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("outstanding commands: %w", err)
	}
	family(&b, "retune_commands_outstanding", "gauge", "Commands not yet finished, by status.")
	for _, s := range commandStatuses {
		sample(&b, "retune_commands_outstanding", "status", s, outstanding[s])
	}

	firing, err := q.FiringAlertCounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("firing alerts: %w", err)
	}
	family(&b, "retune_alerts_firing", "gauge", "Subjects currently firing on enabled alert rules, by rule kind.")
	for _, k := range alertKinds {
		sample(&b, "retune_alerts_firing", "kind", k, firing[k])
	}

	jobs := stats.Snapshot()
	family(&b, "retune_sweeper_runs_total", "counter", "Sweeper job runs in this process, by outcome; skipped means another replica held the lock.")
	for _, j := range jobs {
		for _, res := range runResults {
			fmt.Fprintf(&b, "retune_sweeper_runs_total{job=%s,result=%s} %d\n", quote(j.Name), quote(res), j.Runs[res])
		}
	}
	family(&b, "retune_sweeper_rows_total", "counter", "Rows sweeper jobs have affected in this process.")
	for _, j := range jobs {
		fmt.Fprintf(&b, "retune_sweeper_rows_total{job=%s} %d\n", quote(j.Name), j.Rows)
	}
	family(&b, "retune_sweeper_last_success_timestamp_seconds", "gauge", "When each sweeper job last succeeded in this process; absent until it first does.")
	for _, j := range jobs {
		if !j.LastSuccess.IsZero() {
			fmt.Fprintf(&b, "retune_sweeper_last_success_timestamp_seconds{job=%s} %d\n", quote(j.Name), j.LastSuccess.Unix())
		}
	}

	revision, goVersion := buildInfo()
	family(&b, "retune_build_info", "gauge", "Always 1; the labels say which build is running.")
	fmt.Fprintf(&b, "retune_build_info{revision=%s,go_version=%s} 1\n", quote(revision), quote(goVersion))

	return b.Bytes(), nil
}

func family(b *bytes.Buffer, name, typ, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func sample(b *bytes.Buffer, name, label, value string, n int) {
	fmt.Fprintf(b, "%s{%s=%s} %d\n", name, label, quote(value), n)
}

// quote writes a label value as the exposition format wants it: in double
// quotes, with backslash, quote and newline escaped.
func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) + `"`
}

// buildInfo reads the commit the binary was built from, which go build
// records on its own when it runs inside a checkout.
func buildInfo() (revision, goVersion string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown", "unknown"
	}
	revision = "unknown"
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	if r := settings["vcs.revision"]; r != "" {
		revision = r
		if settings["vcs.modified"] == "true" {
			revision += "-dirty"
		}
	}
	return revision, info.GoVersion
}
