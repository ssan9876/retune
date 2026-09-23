package executor

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"retune/internal/opsign"
	"retune/internal/protocol"
)

// Locker locks the session of whoever is signed in at the console. locked is
// false, with no error, when nobody is.
type Locker interface {
	Lock(ctx context.Context) (locked bool, err error)
}

// EventExporter writes one Windows event log channel's last hours of events
// to path, as an .evtx file.
type EventExporter interface {
	Export(ctx context.Context, channel, path string, hours int) error
}

// ArtifactUploader sends a command's file to the server.
type ArtifactUploader interface {
	UploadCommandArtifact(ctx context.Context, commandID string, body io.Reader, size int64) error
}

// Wiper resets the device. Once it returns nil the reset is under way.
type Wiper interface {
	Wipe(ctx context.Context, protected bool) error
}

// LogSources is what collect_logs gathers.
type LogSources struct {
	// Dir is the agent's data directory: its logs/ folder and update.json.
	Dir string
	// Channels are the event logs exported, such as System and Application.
	Channels []string
	Events   EventExporter
}

var errUnavailable = errors.New("not available on this agent")

func (e *Executor) lock(ctx context.Context, res *protocol.CommandResult) {
	if e.Locker == nil {
		fail(res, "locking "+errUnavailable.Error())
		return
	}
	locked, err := e.Locker.Lock(ctx)
	switch {
	case err != nil:
		fail(res, fmt.Sprintf("locking the session: %v", err))
	case !locked:
		res.Stdout = "nobody is signed in; there is nothing to lock"
	default:
		res.Stdout = "the session is locked"
	}
}

// wipe starts a reset and reports that it has. It reports only once Windows
// has taken the request, so a wipe that couldn't start says so; after that
// the device may reset before the report arrives, and never report again.
func (e *Executor) wipe(ctx context.Context, raw json.RawMessage, res *protocol.CommandResult) {
	var p protocol.WipePayload
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &p); err != nil {
			fail(res, fmt.Sprintf("invalid wipe payload: %v", err))
			return
		}
	}
	if e.Operations.Enforced {
		var expires time.Time
		if p.Expires != nil {
			expires = *p.Expires
		}
		if err := opsign.VerifyWipe(e.Operations.Keys, e.DeviceID, p.Protected, expires, e.now(), p.Signature); err != nil {
			fail(res, "refused: "+err.Error())
			return
		}
	}
	if e.Wiper == nil {
		fail(res, "wiping "+errUnavailable.Error())
		return
	}
	if err := e.Wiper.Wipe(ctx, p.Protected); err != nil {
		fail(res, fmt.Sprintf("starting the wipe: %v", err))
		return
	}
	res.Stdout = "wipe started; the device is resetting and won't report again until it is enrolled anew"
}

// collectLogs builds the archive in a temporary file, then uploads it.
func (e *Executor) collectLogs(ctx context.Context, c protocol.Command, res *protocol.CommandResult) {
	p := protocol.CollectLogsPayload{Hours: protocol.DefaultLogHours}
	if len(c.Payload) > 0 && string(c.Payload) != "null" {
		if err := json.Unmarshal(c.Payload, &p); err != nil {
			fail(res, fmt.Sprintf("invalid collect_logs payload: %v", err))
			return
		}
	}
	if e.Uploader == nil || e.Logs.Dir == "" {
		fail(res, "collecting logs "+errUnavailable.Error())
		return
	}
	tmp, err := os.MkdirTemp(e.Logs.Dir, "collect-*")
	if err != nil {
		fail(res, err.Error())
		return
	}
	defer os.RemoveAll(tmp)
	archive := filepath.Join(tmp, "logs.zip")
	notes, err := BuildLogArchive(ctx, e.Logs, p.Hours, archive, tmp, protocol.MaxLogArchiveBytes)
	if err != nil {
		fail(res, fmt.Sprintf("building the archive: %v", err))
		return
	}
	f, err := os.Open(archive)
	if err != nil {
		fail(res, err.Error())
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		fail(res, err.Error())
		return
	}
	if err := e.Uploader.UploadCommandArtifact(ctx, c.ID, f, info.Size()); err != nil {
		fail(res, fmt.Sprintf("uploading the archive: %v", err))
		res.Stdout = strings.Join(notes, "\n")
		return
	}
	res.Stdout = strings.Join(append(notes, fmt.Sprintf("uploaded %d bytes", info.Size())), "\n")
}

// BuildLogArchive zips the agent's logs, its update record and the recent
// event logs into path, keeping the archive under max bytes: something that
// doesn't fit is left out and noted, not the whole collection failed. work
// is a scratch directory for event log exports.
func BuildLogArchive(ctx context.Context, src LogSources, hours int, path, work string, max int64) ([]string, error) {
	type item struct{ name, file string }
	var items []item
	var notes []string

	logDir := filepath.Join(src.Dir, "logs")
	entries, err := os.ReadDir(logDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		notes = append(notes, "no agent logs")
	case err != nil:
		notes = append(notes, fmt.Sprintf("agent logs unreadable: %v", err))
	default:
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			if e.Type().IsRegular() {
				items = append(items, item{"agent/" + e.Name(), filepath.Join(logDir, e.Name())})
			}
		}
	}
	if _, err := os.Stat(filepath.Join(src.Dir, "update.json")); err == nil {
		items = append(items, item{"agent/update.json", filepath.Join(src.Dir, "update.json")})
	}
	for _, ch := range src.Channels {
		if src.Events == nil {
			break
		}
		out := filepath.Join(work, ch+".evtx")
		if err := src.Events.Export(ctx, ch, out, hours); err != nil {
			notes = append(notes, fmt.Sprintf("%s event log: %v", ch, err))
			continue
		}
		items = append(items, item{"events/" + ch + ".evtx", out})
	}

	f, err := os.Create(path)
	if err != nil {
		return notes, err
	}
	defer f.Close()
	counted := &countingWriter{w: f}
	zw := zip.NewWriter(counted)
	for _, it := range items {
		if err := ctx.Err(); err != nil {
			return notes, err
		}
		info, err := os.Stat(it.file)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: %v", it.name, err))
			continue
		}
		// Worst case, a file doesn't compress at all; leave room for the
		// zip's own bookkeeping too.
		if counted.n+info.Size()+64<<10 > max {
			notes = append(notes, fmt.Sprintf("%s left out: the archive would pass %d MiB", it.name, max>>20))
			continue
		}
		if err := addFile(zw, it.name, it.file, info.ModTime()); err != nil {
			notes = append(notes, fmt.Sprintf("%s: %v", it.name, err))
			continue
		}
		if err := zw.Flush(); err != nil {
			return notes, err
		}
		notes = append(notes, "included "+it.name)
	}
	if err := zw.Close(); err != nil {
		return notes, err
	}
	return notes, f.Close()
}

func addFile(zw *zip.Writer, name, path string, mod time.Time) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: mod})
	if err != nil {
		return err
	}
	_, err = io.Copy(w, src)
	return err
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
