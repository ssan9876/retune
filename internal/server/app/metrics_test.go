package app_test

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"retune/internal/config"
	"retune/internal/protocol"
	"retune/internal/server/app"
	"retune/internal/server/store"
	"retune/internal/server/sweeper"
)

const testMetricsToken = "metrics-token-for-tests-0123456789abcdef"

func scrape(t *testing.T, a *app.App, url, auth string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	res, err := httpClient(a, nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

// samples parses the exposition line by line into "name{labels}" -> value,
// and fails on any line that is neither a comment nor a sample.
func samples(t *testing.T, body string) map[string]string {
	t.Helper()
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "# HELP ") || strings.HasPrefix(line, "# TYPE ") {
			continue
		}
		i := strings.LastIndex(line, " ")
		if i < 0 || !strings.Contains(line[:i], "{") {
			t.Fatalf("not a sample line: %q", line)
		}
		out[line[:i]] = line[i+1:]
	}
	return out
}

func TestMetricsAreOffWithoutAToken(t *testing.T) {
	a, srv := newTestApp(t)
	if status, _ := scrape(t, a, srv.URL, "Bearer anything"); status != http.StatusNotFound {
		t.Fatalf("with no token configured /metrics should not exist, got %d", status)
	}
}

func TestMetricsNeedTheToken(t *testing.T) {
	a, srv := newTestAppWith(t, func(c *config.Server) { c.MetricsToken = testMetricsToken })
	for _, auth := range []string{"", "Bearer wrong", testMetricsToken, "Basic " + testMetricsToken} {
		if status, _ := scrape(t, a, srv.URL, auth); status != http.StatusUnauthorized {
			t.Errorf("Authorization %q: want 401, got %d", auth, status)
		}
	}
}

func TestMetricsDescribeTheFleetAndTheSweepers(t *testing.T) {
	a, srv := newTestAppWith(t, func(c *config.Server) { c.MetricsToken = testMetricsToken })
	ctx := context.Background()

	// One device that has checked in, with one command waiting for it.
	id, agent := enrollDevice(t, a, srv, "METRICS-PC")
	if status, body := send(t, agent, http.MethodPost, srv.URL+"/api/agent/v1/checkin",
		protocol.CheckinRequest{AgentVersion: "1.0.0"}); status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, body)
	}
	now := time.Now().UTC()
	if err := a.Store.Q().CreateCommand(ctx, store.Command{
		ID: uuid.Must(uuid.NewV7()), DeviceID: id, Type: "restart", Payload: []byte(`{}`),
		Status: "queued", CreatedBy: "test", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// A sweeper job run through the app's own recorder shows up too.
	r := &sweeper.Runner{Store: a.Store, Now: time.Now, Stats: a.Sweeps}
	if _, _, err := r.RunOnce(ctx, sweeper.Job{Name: "test.job", LockID: 991101, Interval: time.Hour,
		Run: func(context.Context, *store.Queries, time.Time) (int64, error) { return 7, nil }}); err != nil {
		t.Fatal(err)
	}

	status, body := scrape(t, a, srv.URL, "Bearer "+testMetricsToken)
	if status != http.StatusOK {
		t.Fatalf("scrape: %d %s", status, body)
	}
	got := samples(t, body)
	want := map[string]string{
		`retune_devices{state="active"}`:                           "1",
		`retune_devices{state="stale"}`:                            "0",
		`retune_devices{state="retired"}`:                          "0",
		`retune_compliance_devices{state="not_evaluated"}`:         "1",
		`retune_compliance_devices{state="non_compliant"}`:         "0",
		`retune_failed_deployments{kind="script"}`:                 "0",
		`retune_commands_outstanding{status="queued"}`:             "1",
		`retune_commands_outstanding{status="running"}`:            "0",
		`retune_alerts_firing{kind="device_stale"}`:                "0",
		`retune_sweeper_runs_total{job="test.job",result="ok"}`:    "1",
		`retune_sweeper_runs_total{job="test.job",result="error"}`: "0",
		`retune_sweeper_rows_total{job="test.job"}`:                "7",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got[`retune_sweeper_last_success_timestamp_seconds{job="test.job"}`]; !ok {
		t.Error("the job's last success should be reported")
	}
	found := false
	for k, v := range got {
		if strings.HasPrefix(k, "retune_build_info{") && v == "1" {
			found = true
		}
	}
	if !found {
		t.Error("retune_build_info should be present")
	}
}

// A scrape is all or nothing: if the database cannot answer, the whole page
// is an error rather than a page of zeros.
func TestMetricsFailWholeWhenTheDatabaseDoes(t *testing.T) {
	a, srv := newTestAppWith(t, func(c *config.Server) { c.MetricsToken = testMetricsToken })
	a.Store.Close()
	if status, body := scrape(t, a, srv.URL, "Bearer "+testMetricsToken); status != http.StatusInternalServerError ||
		strings.Contains(body, "retune_devices") {
		t.Fatalf("want a bare 500, got %d %q", status, body)
	}
}
