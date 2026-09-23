package executor

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"retune/internal/protocol"
)

type fakeLocker struct {
	locked bool
	err    error
	calls  int
}

func (f *fakeLocker) Lock(context.Context) (bool, error) {
	f.calls++
	return f.locked, f.err
}

type fakeWiper struct {
	protected []bool
	err       error
}

func (f *fakeWiper) Wipe(_ context.Context, protected bool) error {
	f.protected = append(f.protected, protected)
	return f.err
}

type fakeExporter struct {
	body map[string]string // channel -> contents
	err  map[string]error
}

func (f fakeExporter) Export(_ context.Context, channel, path string, _ int) error {
	if err := f.err[channel]; err != nil {
		return err
	}
	return os.WriteFile(path, []byte(f.body[channel]), 0o600)
}

type fakeUploader struct {
	id   string
	body []byte
	size int64
	err  error
}

func (f *fakeUploader) UploadCommandArtifact(_ context.Context, id string, body io.Reader, size int64) error {
	f.id, f.size = id, size
	f.body, _ = io.ReadAll(body)
	return f.err
}

func TestLock(t *testing.T) {
	for name, c := range map[string]struct {
		locker *fakeLocker
		status string
		stdout string
	}{
		"someone signed in": {&fakeLocker{locked: true}, protocol.ResultSucceeded, "the session is locked"},
		"nobody signed in":  {&fakeLocker{}, protocol.ResultSucceeded, "nobody is signed in; there is nothing to lock"},
		"lock fails":        {&fakeLocker{err: errors.New("access denied")}, protocol.ResultFailed, ""},
	} {
		e := &Executor{Locker: c.locker}
		res := e.Execute(context.Background(), cmd(t, protocol.CommandLock, nil))
		if res.Status != c.status || res.Stdout != c.stdout {
			t.Errorf("%s: = %+v", name, res)
		}
	}
	// No locker (not Windows): a plain failure, not a panic.
	if res := (&Executor{}).Execute(context.Background(), cmd(t, protocol.CommandLock, nil)); res.Status != protocol.ResultFailed {
		t.Errorf("no locker = %+v", res)
	}
}

func TestWipe(t *testing.T) {
	w := &fakeWiper{}
	e := &Executor{Wiper: w}
	res := e.Execute(context.Background(), cmd(t, protocol.CommandWipe, protocol.WipePayload{Protected: true}))
	if res.Status != protocol.ResultSucceeded || !strings.Contains(res.Stdout, "wipe started") {
		t.Fatalf("wipe = %+v", res)
	}
	if len(w.protected) != 1 || !w.protected[0] {
		t.Fatalf("wiper called with %v", w.protected)
	}

	// A wipe Windows refused is reported as failed, never as started.
	w.err = errors.New("MDM_RemoteWipe: not found")
	res = e.Execute(context.Background(), cmd(t, protocol.CommandWipe, protocol.WipePayload{}))
	if res.Status != protocol.ResultFailed || !strings.Contains(res.Error, "MDM_RemoteWipe") {
		t.Fatalf("refused wipe = %+v", res)
	}
	if res := (&Executor{}).Execute(context.Background(), cmd(t, protocol.CommandWipe, nil)); res.Status != protocol.ResultFailed {
		t.Errorf("no wiper = %+v", res)
	}
}

func dataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"agent.log": "today", "agent.log.1": "yesterday"} {
		if err := os.WriteFile(filepath.Join(dir, "logs", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "update.json"), []byte(`{"version":"1.2.3"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func zipContents(t *testing.T, body []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = string(b)
	}
	return out
}

func TestCollectLogs(t *testing.T) {
	dir := dataDir(t)
	up := &fakeUploader{}
	e := &Executor{Uploader: up, Logs: LogSources{
		Dir: dir, Channels: []string{"System", "Application"},
		Events: fakeExporter{
			body: map[string]string{"System": "system events"},
			err:  map[string]error{"Application": errors.New("access denied")},
		},
	}}
	c := cmd(t, protocol.CommandCollectLogs, protocol.CollectLogsPayload{Hours: 6})
	res := e.Execute(context.Background(), c)
	if res.Status != protocol.ResultSucceeded {
		t.Fatalf("collect_logs = %+v", res)
	}
	if up.id != c.ID || up.size != int64(len(up.body)) {
		t.Fatalf("uploaded %q, %d bytes (said %d)", up.id, len(up.body), up.size)
	}
	got := zipContents(t, up.body)
	want := map[string]string{
		"agent/agent.log": "today", "agent/agent.log.1": "yesterday",
		"agent/update.json": `{"version":"1.2.3"}`, "events/System.evtx": "system events",
	}
	for name, body := range want {
		if got[name] != body {
			t.Errorf("%s = %q, want %q", name, got[name], body)
		}
	}
	if len(got) != len(want) {
		t.Errorf("archive has %v", got)
	}
	// A channel that couldn't be exported is noted, not fatal.
	if !strings.Contains(res.Stdout, "Application event log: access denied") {
		t.Errorf("stdout = %q", res.Stdout)
	}
	// The scratch directory is gone.
	if matches, _ := filepath.Glob(filepath.Join(dir, "collect-*")); len(matches) != 0 {
		t.Errorf("left %v behind", matches)
	}

	// An upload the server refused is a failure.
	up.err = errors.New("409 conflict")
	if res := e.Execute(context.Background(), c); res.Status != protocol.ResultFailed {
		t.Errorf("refused upload = %+v", res)
	}
}

func TestLogArchiveStaysUnderTheCap(t *testing.T) {
	dir := dataDir(t)
	big := bytes.Repeat([]byte("x"), 200<<10)
	if err := os.WriteFile(filepath.Join(dir, "logs", "huge.log"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	path := filepath.Join(work, "logs.zip")
	notes, err := BuildLogArchive(context.Background(), LogSources{Dir: dir}, 24, path, work, 150<<10)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Size() > 150<<10 {
		t.Fatalf("archive is %d bytes, over the cap", info.Size())
	}
	body, _ := os.ReadFile(path)
	got := zipContents(t, body)
	if _, ok := got["agent/huge.log"]; ok {
		t.Error("a file that could pass the cap was included")
	}
	if got["agent/agent.log"] != "today" {
		t.Error("the files that fit were left out")
	}
	if !strings.Contains(strings.Join(notes, "\n"), "agent/huge.log left out") {
		t.Errorf("notes = %v", notes)
	}
}
