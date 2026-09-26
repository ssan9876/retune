package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"retune/internal/config"
	"retune/internal/server/releasefeed"
	"retune/internal/server/store"
	"retune/internal/serverupdate"
	"retune/internal/version"
)

// serverUpdateLockID keeps two replicas - or two clicks - from handing over an
// update at once.
const serverUpdateLockID = 5274014

// serverJSON is the server's version and whether a newer one can be installed.
type serverJSON struct {
	Version string `json:"version"`
	// Stamped is false for a development build, which reports 0.0.0-dev.
	Stamped bool `json:"stamped"`
	// Mode is how an update would be applied: docker, binary or none.
	Mode string `json:"mode"`
	// ModeNote says why updates cannot be applied from the console, if not.
	ModeNote string `json:"mode_note,omitempty"`
	// Latest is the newest verified release the release feed has found.
	Latest      *latestReleaseJSON `json:"latest,omitempty"`
	LatestError string             `json:"latest_error,omitempty"`
	// UpdateAvailable is Latest being newer than Version.
	UpdateAvailable bool `json:"update_available"`
	// State is the latest update's progress, or how it ended.
	State *serverupdate.State `json:"state,omitempty"`
	// PendingApprovalID is an update waiting for a second administrator.
	PendingApprovalID string `json:"pending_approval_id,omitempty"`
	ApprovalsRequired bool   `json:"approvals_required"`
}

type latestReleaseJSON struct {
	Version     string    `json:"version"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Notes       string    `json:"notes"`
}

// serverUpdateRequest asks for the server to be updated to a version, which
// must be the newest verified release.
type serverUpdateRequest struct {
	Version string `json:"version"`
}

type serverUpdateResponse struct {
	State *serverupdate.State `json:"state"`
}

// refusal is an update request that cannot go ahead as things stand.
type refusal struct {
	code, msg string
}

func (r refusal) Error() string { return r.msg }

// serverUpdater is how this server applies updates, or why it cannot.
func (h *Handler) serverUpdater() (serverupdate.Client, string) {
	cfg := h.ServerUpdateConfig
	docker := serverupdate.SocketClient{Path: cfg.UpdaterSocket, Token: cfg.UpdaterToken}
	switch cfg.Mode {
	case config.ServerUpdateOff:
		return nil, "Updating from the console is turned off (SERVER_UPDATE_MODE=off)."
	case config.ServerUpdateDocker:
		return docker, ""
	case config.ServerUpdateBinary:
		src := h.releaseSource()
		if src == nil {
			return nil, "The release feed is not configured."
		}
		return serverupdate.BinaryClient{Dir: cfg.Dir, Source: src}, ""
	}
	if docker.Ready() == nil {
		return docker, ""
	}
	return nil, "No updater is running. Add the updater service to the Compose stack, or for a binary install set SERVER_UPDATE_MODE=binary."
}

// releaseSource is where the release feed downloads from.
func (h *Handler) releaseSource() releasefeed.Source {
	if h.ReleaseFeed == nil || h.ReleaseFeed.Source == nil {
		return nil
	}
	return h.ReleaseFeed.Source
}

// latestRelease is the newest verified release this server may install.
func (h *Handler) latestRelease(ctx context.Context) (*latestReleaseJSON, serverupdate.Staged, error) {
	if h.ReleaseFeed == nil {
		return nil, serverupdate.Staged{}, errors.New("the release feed is not configured")
	}
	rel, m, err := h.ReleaseFeed.Latest(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil, serverupdate.Staged{}, nil
	}
	if err != nil {
		return nil, serverupdate.Staged{}, err
	}
	if rel.Prerelease && !h.ReleaseFeedConfig.Prereleases {
		return nil, serverupdate.Staged{}, nil
	}
	return &latestReleaseJSON{Version: rel.Version, Prerelease: rel.Prerelease, PublishedAt: rel.PublishedAt, Notes: rel.Notes},
		serverupdate.Staged{Manifest: m, Raw: rel.Manifest, Signature: rel.Signature}, nil
}

// getServer reports the running version, the newest release, and any update
// in progress.
func (h *Handler) getServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := serverJSON{
		Version: version.Version, Stamped: version.Stamped(), Mode: serverupdate.ModeNone,
		ApprovalsRequired: h.ApprovalsRequired,
	}
	latest, _, err := h.latestRelease(ctx)
	if err != nil {
		out.LatestError = err.Error()
	}
	if latest != nil {
		out.Latest = latest
		out.UpdateAvailable = serverupdate.Newer(latest.Version, version.Version)
	}
	client, note := h.serverUpdater()
	out.ModeNote = note
	if client != nil {
		out.Mode = client.Mode()
		if err := client.Ready(); err != nil {
			out.ModeNote = err.Error()
		} else if st, err := client.Status(ctx); err != nil {
			out.ModeNote = "The updater did not answer: " + err.Error()
		} else {
			out.State = st
		}
	}
	pending, _, err := h.Store.Q().ListApprovals(ctx, store.ApprovalPending, store.Page{Limit: 200})
	if err != nil {
		h.internal(w, "list approvals", err)
		return
	}
	for _, a := range pending {
		if a.Kind == store.ApprovalServerUpdate {
			out.PendingApprovalID = a.ID.String()
			break
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// requestServerUpdate updates the server to the newest verified release, or
// holds the request for a second administrator when approvals are on.
func (h *Handler) requestServerUpdate(w http.ResponseWriter, r *http.Request) {
	var req serverUpdateRequest
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	latest, _, err := h.checkServerUpdate(ctx, req.Version)
	if h.writeRefusal(w, err) {
		return
	}
	if h.ApprovalsRequired {
		h.holdForApproval(w, r, store.ApprovalServerUpdate, serverUpdateRequest{Version: latest.Version},
			fmt.Sprintf("Update the Retune server from %s to %s", version.Version, latest.Version))
		return
	}
	st, err := h.startServerUpdate(ctx, req.Version, caller(r).Admin.Email)
	if h.writeRefusal(w, err) {
		return
	}
	writeJSON(w, http.StatusAccepted, serverUpdateResponse{State: st})
}

func (h *Handler) writeRefusal(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var ref refusal
	if errors.As(err, &ref) {
		writeError(w, http.StatusConflict, ref.code, ref.msg)
		return true
	}
	h.internal(w, "server update", err)
	return true
}

// checkServerUpdate refuses an update that should not happen: to anything but
// the newest verified release, to a version not newer than this one, or with
// nothing to apply it.
func (h *Handler) checkServerUpdate(ctx context.Context, want string) (*latestReleaseJSON, serverupdate.Staged, error) {
	latest, staged, err := h.latestRelease(ctx)
	if err != nil {
		return nil, serverupdate.Staged{}, refusal{"no_release", "no verified release can be read: " + err.Error()}
	}
	if latest == nil {
		return nil, serverupdate.Staged{}, refusal{"no_release", "the release feed has not found a verified release"}
	}
	if want != latest.Version {
		return nil, serverupdate.Staged{}, refusal{"not_latest",
			fmt.Sprintf("only the newest verified release, %s, can be installed", latest.Version)}
	}
	if !serverupdate.Newer(latest.Version, version.Version) {
		return nil, serverupdate.Staged{}, refusal{"not_newer",
			fmt.Sprintf("%s is not newer than the running %s; the server is never downgraded", latest.Version, version.Version)}
	}
	client, note := h.serverUpdater()
	if client == nil {
		return nil, serverupdate.Staged{}, refusal{"no_updater", note}
	}
	if err := client.Ready(); err != nil {
		return nil, serverupdate.Staged{}, refusal{"no_updater", err.Error()}
	}
	return latest, staged, nil
}

// startServerUpdate hands the update to the updater, holding a lock so two
// replicas cannot both start one.
func (h *Handler) startServerUpdate(ctx context.Context, want, requestedBy string) (*serverupdate.State, error) {
	var st *serverupdate.State
	var startErr error
	ran, err := h.Store.WithAdvisoryLock(ctx, serverUpdateLockID, func(*store.Queries) error {
		_, staged, err := h.checkServerUpdate(ctx, want)
		if err != nil {
			startErr = err
			return nil
		}
		client, _ := h.serverUpdater()
		if cur, err := client.Status(ctx); err == nil && cur != nil && !cur.Done() {
			startErr = refusal{"busy", serverupdate.ErrBusy.Error()}
			return nil
		}
		req := serverupdate.Request{
			ID: uuid.Must(uuid.NewV7()).String(), Version: want, RequestedBy: requestedBy, RequestedAt: h.Now(),
		}
		if err := client.Start(ctx, req, staged); err != nil {
			if errors.Is(err, serverupdate.ErrBusy) {
				startErr = refusal{"busy", err.Error()}
				return nil
			}
			startErr = fmt.Errorf("start the update: %w", err)
			return nil
		}
		if err := h.Store.Q().InsertAudit(ctx, store.AuditEntry{
			Actor: requestedBy, Action: "server.update_started", TargetKind: "server", TargetID: req.ID,
			Details: map[string]any{"from": version.Version, "to": want, "mode": client.Mode()},
		}); err != nil {
			return err
		}
		st, _ = client.Status(ctx)
		if st == nil {
			st = &serverupdate.State{ID: req.ID, Version: want, Phase: serverupdate.PhaseQueued, RequestedBy: requestedBy}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !ran {
		return nil, refusal{"busy", "another server is starting an update"}
	}
	return st, startErr
}
