// Package session performs one check-in cycle: renew the certificate when due,
// flush queued results, check in, upload inventory, and dispatch commands to a
// background worker.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"retune/internal/agent/apps"
	"retune/internal/agent/checkin"
	"retune/internal/agent/client"
	"retune/internal/agent/enrollment"
	"retune/internal/agent/executor"
	"retune/internal/agent/identity"
	"retune/internal/agent/inventory"
	"retune/internal/agent/policy"
	"retune/internal/agent/scripts"
	"retune/internal/agent/selfupdate"
	"retune/internal/agent/state"
	"retune/internal/protocol"
)

// DefaultRenewBefore is how long before expiry the certificate is renewed.
const DefaultRenewBefore = 30 * 24 * time.Hour

// ledgerRetention is how long finished commands stay in the local ledger.
const ledgerRetention = 30 * 24 * time.Hour

// workQueueSize bounds commands waiting to run; anything beyond it is offered
// again at the next check-in.
const workQueueSize = 64

// Config wires a Session.
type Config struct {
	Identity  *identity.Identity
	IDStore   identity.Store
	State     *state.Store
	Collector inventory.Collector
	Executor  *executor.Executor
	// Scripts, when set, applies the deployments assigned to this device.
	Scripts *scripts.Scheduler
	// Policy, when set, reconciles the configuration profiles assigned to this
	// device.
	Policy *policy.Syncer
	// Apps, when set, installs and removes the apps assigned to this device.
	Apps *apps.Syncer
	// SelfUpdate, when set, replaces this agent with an assigned build.
	SelfUpdate *selfupdate.Syncer
	// Syncers apply what is assigned to this device. New appends Scripts and
	// Policy to whatever is set here.
	Syncers     []ItemSyncer
	Log         *slog.Logger
	Now         func() time.Time
	RenewBefore time.Duration
}

// ItemSyncer applies one kind of assigned work. The agent hands every syncer
// the whole item list and each filters it, so a kind nobody handles is simply
// ignored.
type ItemSyncer interface {
	Sync(ctx context.Context, items []protocol.Item) error
	// RunOnEmpty reports whether Sync must be called even when nothing is
	// assigned. Profiles say yes: an empty list is exactly when a profile that
	// has just been unassigned must be undone.
	RunOnEmpty() bool
	// Name identifies the subsystem in the agent's log.
	Name() string
}

// Session is the agent's connection to its server plus its local state.
type Session struct {
	cfg Config

	mu       sync.Mutex // guards id, client and inflight
	id       *identity.Identity
	client   *client.Client
	inflight map[string]bool

	flushMu sync.Mutex // one result flush at a time
	work    chan protocol.Command
	pending sync.WaitGroup
}

// New builds a Session for an enrolled identity.
func New(cfg Config) (*Session, error) {
	if cfg.Identity == nil || cfg.State == nil || cfg.Collector == nil || cfg.Executor == nil {
		return nil, errors.New("session: Identity, State, Collector and Executor are required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RenewBefore <= 0 {
		cfg.RenewBefore = DefaultRenewBefore
	}
	c, err := enrollment.Connect(cfg.Identity)
	if err != nil {
		return nil, err
	}
	s := &Session{
		cfg: cfg, id: cfg.Identity, client: c,
		inflight: map[string]bool{},
		work:     make(chan protocol.Command, workQueueSize),
	}
	if cfg.Executor.RefreshInventory == nil {
		cfg.Executor.RefreshInventory = s.UploadInventory
	}
	if cfg.Scripts != nil && cfg.Scripts.Client == nil {
		cfg.Scripts.Client = scriptClient{s}
	}
	if cfg.Apps != nil && cfg.Apps.Client == nil {
		cfg.Apps.Client = appClient{s}
	}
	if cfg.Apps != nil {
		if pk, ok := cfg.Apps.Packages.(*apps.Packages); ok && pk.Download == nil {
			pk.Download = appClient{s}
		}
	}
	if cfg.SelfUpdate != nil && cfg.SelfUpdate.Client == nil {
		cfg.SelfUpdate.Client = selfUpdateClient{s}
	}
	if cfg.Policy != nil {
		if cfg.Policy.Fetcher == nil {
			cfg.Policy.Fetcher = policyClient{s}
		}
		if cfg.Policy.Reconciler != nil && cfg.Policy.Reconciler.Client == nil {
			cfg.Policy.Reconciler.Client = policyClient{s}
		}
		// The BitLocker handler escrows through the same client, so a
		// certificate renewal is picked up there too.
		if cfg.Policy.Reconciler != nil && len(cfg.Policy.Reconciler.Handlers) == 0 {
			cfg.Policy.Reconciler.Handlers = policy.DefaultHandlers(policyClient{s})
		}
	}
	if cfg.Scripts != nil {
		s.cfg.Syncers = append(s.cfg.Syncers, scriptSyncer{cfg.Scripts})
	}
	if cfg.Policy != nil {
		s.cfg.Syncers = append(s.cfg.Syncers, policySyncer{cfg.Policy})
	}
	if cfg.Apps != nil {
		s.cfg.Syncers = append(s.cfg.Syncers, appSyncer{cfg.Apps})
	}
	if cfg.SelfUpdate != nil {
		s.cfg.Syncers = append(s.cfg.Syncers, selfUpdateSyncer{cfg.SelfUpdate})
	}
	return s, nil
}

// dispatch starts each syncer that has something to do. It is separate from
// Checkin so the rule about empty item lists can be tested without an enrolled
// identity and a server to talk to.
func dispatch(ctx context.Context, syncers []ItemSyncer, items []protocol.Item,
	pending *sync.WaitGroup, log *slog.Logger) {
	for _, syncer := range syncers {
		if len(items) == 0 && !syncer.RunOnEmpty() {
			continue
		}
		pending.Add(1)
		go func() {
			defer pending.Done()
			if err := syncer.Sync(ctx, items); err != nil {
				log.Warn("applying assigned work failed", "syncer", syncer.Name(), "error", err)
			}
		}()
	}
}

// Start launches the command worker and prunes the old ledger.
func (s *Session) Start(ctx context.Context) {
	if n, err := s.cfg.State.PruneLedger(s.cfg.Now().Add(-ledgerRetention)); err != nil {
		s.cfg.Log.Warn("pruning the command ledger failed", "error", err)
	} else if n > 0 {
		s.cfg.Log.Debug("pruned old command ledger entries", "count", n)
	}
	go s.worker(ctx)
}

// Wait blocks until every queued command has run and its result is stored.
func (s *Session) Wait() { s.pending.Wait() }

// Checkin performs one full cycle. It satisfies checkin.Checker.
func (s *Session) Checkin(ctx context.Context, req protocol.CheckinRequest) (protocol.CheckinResponse, error) {
	if err := s.maybeRenew(ctx); err != nil {
		s.cfg.Log.Warn("renewing the client certificate failed", "error", err)
	}
	if err := s.FlushResults(ctx); err != nil {
		s.cfg.Log.Warn("sending queued command results failed", "error", err)
	}

	hash, err := s.cfg.State.InventoryHash()
	if err != nil {
		return protocol.CheckinResponse{}, fmt.Errorf("read stored inventory hash: %w", err)
	}
	req.InventoryHash = hash

	resp, err := s.currentClient().Checkin(ctx, req)
	var httpErr *client.HTTPError
	if errors.As(err, &httpErr) && httpErr.Status == http.StatusGone {
		s.wipe()
		return resp, fmt.Errorf("%w: %s", checkin.ErrUnenrolled, httpErr.Message)
	}
	if err != nil {
		return resp, err
	}

	// The server accepted this check-in, which is the only thing that proves
	// a freshly installed build actually works. It is told here rather than
	// from the self-update syncer's own Sync, because Sync does not run when
	// nothing is assigned: an administrator who unassigns the build between
	// the hand-off and the restart would otherwise starve the supervisor of
	// its proof and force a rollback of a perfectly good agent.
	s.noteCheckedIn()

	if resp.InventoryDue {
		if err := s.UploadInventory(ctx); err != nil {
			s.cfg.Log.Warn("uploading inventory failed", "error", err)
		}
	}
	for _, cmd := range resp.Commands {
		s.enqueue(cmd)
	}
	// Assigned work is applied in the background: a long-running deployment
	// must not hold up check-ins, inventory or commands. Each syncer runs one
	// job at a time internally, so a slow one only means the next check-in
	// finds it still busy.
	dispatch(ctx, s.cfg.Syncers, resp.Items, &s.pending, s.cfg.Log)
	return resp, nil
}

// noteCheckedIn passes the proof of life on to the self-update syncer, if
// there is one. A failure here is worth a line in the log and nothing more:
// the check-in itself succeeded, and the worst case is that the supervisor
// rolls an update back that would have stood.
func (s *Session) noteCheckedIn() {
	if s.cfg.SelfUpdate == nil {
		return
	}
	if err := s.cfg.SelfUpdate.CheckedIn(); err != nil {
		s.cfg.Log.Warn("recording proof of life for a pending self-update failed", "error", err)
	}
}

// UploadInventory collects and uploads inventory, then records the hash the
// server acknowledged.
func (s *Session) UploadInventory(ctx context.Context) error {
	inv, err := s.cfg.Collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collect inventory: %w", err)
	}
	resp, err := s.currentClient().PutInventory(ctx, inv)
	if err != nil {
		return err
	}
	return s.cfg.State.SetInventoryHash(resp.Hash)
}

// FlushResults sends queued command results, dropping any the server rejects
// outright and keeping the rest for the next attempt.
func (s *Session) FlushResults(ctx context.Context) error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	pending, err := s.cfg.State.PendingResults()
	if err != nil {
		return err
	}
	for _, qr := range pending {
		err := s.currentClient().SubmitResult(ctx, qr.CommandID, qr.Result)
		var httpErr *client.HTTPError
		switch {
		case err == nil:
		case errors.As(err, &httpErr) && (httpErr.Status == http.StatusNotFound || httpErr.Status == http.StatusBadRequest):
			s.cfg.Log.Warn("server rejected a command result; dropping it",
				"command_id", qr.CommandID, "status", httpErr.Status, "message", httpErr.Message)
		default:
			return err
		}
		if err := s.cfg.State.DeleteResult(qr.CommandID); err != nil {
			return err
		}
	}
	return nil
}

// enqueue hands a command to the worker unless it is already running or the
// ledger shows it was handled.
func (s *Session) enqueue(cmd protocol.Command) {
	s.mu.Lock()
	if s.inflight[cmd.ID] {
		s.mu.Unlock()
		return
	}
	ledger, err := s.cfg.State.LedgerState(cmd.ID)
	if err != nil {
		s.mu.Unlock()
		s.cfg.Log.Warn("reading the command ledger failed", "command_id", cmd.ID, "error", err)
		return
	}
	switch ledger {
	case state.LedgerCompleted:
		// Already run; its result is queued or already sent.
		s.mu.Unlock()
		return
	case state.LedgerStarted:
		// Started before the agent stopped, so it never reported back.
		s.mu.Unlock()
		now := s.cfg.Now()
		s.finish(cmd.ID, protocol.CommandResult{
			Status: protocol.ResultFailed, ExitCode: -1,
			Error:     "the agent restarted while this command was running",
			StartedAt: now, FinishedAt: now,
		})
		return
	}
	select {
	case s.work <- cmd:
		s.inflight[cmd.ID] = true
		s.pending.Add(1)
	default:
		s.cfg.Log.Warn("command queue is full; will retry at the next check-in", "command_id", cmd.ID)
	}
	s.mu.Unlock()
}

func (s *Session) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-s.work:
			s.run(ctx, cmd)
		}
	}
}

func (s *Session) run(ctx context.Context, cmd protocol.Command) {
	defer func() {
		s.mu.Lock()
		delete(s.inflight, cmd.ID)
		s.mu.Unlock()
		s.pending.Done()
	}()
	defer func() {
		if r := recover(); r != nil {
			s.cfg.Log.Error("command execution panicked", "command_id", cmd.ID, "panic", r)
			now := s.cfg.Now()
			s.finish(cmd.ID, protocol.CommandResult{
				Status: protocol.ResultFailed, ExitCode: -1,
				Error:     fmt.Sprintf("the agent panicked while running this command: %v", r),
				StartedAt: now, FinishedAt: now,
			})
		}
	}()

	if _, err := s.cfg.State.MarkStarted(cmd.ID, s.cfg.Now()); err != nil {
		s.cfg.Log.Error("recording command start failed", "command_id", cmd.ID, "error", err)
		return
	}
	if err := s.currentClient().StartCommand(ctx, cmd.ID); err != nil {
		s.cfg.Log.Warn("reporting command start failed", "command_id", cmd.ID, "error", err)
	}
	result := s.cfg.Executor.Execute(ctx, cmd)
	s.finish(cmd.ID, result)
	if err := s.FlushResults(ctx); err != nil {
		s.cfg.Log.Warn("sending the command result failed; it stays queued", "command_id", cmd.ID, "error", err)
	}
}

// finish stores a result before marking the command done, so a crash in between
// leaves the result to be sent rather than losing it.
func (s *Session) finish(id string, r protocol.CommandResult) {
	if err := s.cfg.State.QueueResult(state.QueuedResult{CommandID: id, Result: r}); err != nil {
		s.cfg.Log.Error("queueing a command result failed", "command_id", id, "error", err)
		return
	}
	if err := s.cfg.State.MarkCompleted(id, s.cfg.Now()); err != nil {
		s.cfg.Log.Error("recording command completion failed", "command_id", id, "error", err)
	}
}

// maybeRenew replaces the client certificate when it is close to expiry.
func (s *Session) maybeRenew(ctx context.Context) error {
	s.mu.Lock()
	id := s.id
	s.mu.Unlock()

	notAfter, err := id.CertNotAfter()
	if err != nil {
		return err
	}
	if s.cfg.Now().Add(s.cfg.RenewBefore).Before(notAfter) {
		return nil
	}
	key, csrPEM, err := identity.NewKeyAndCSR(id.DeviceID)
	if err != nil {
		return err
	}
	resp, err := s.currentClient().Renew(ctx, protocol.RenewRequest{CSRPEM: csrPEM})
	if err != nil {
		return err
	}
	next := *id
	next.CertPEM = resp.CertPEM
	next.Key = key
	// Save before switching: the server keeps accepting the old certificate
	// until the new one is used, so a failure here is recoverable.
	if err := s.cfg.IDStore.Save(&next); err != nil {
		return fmt.Errorf("save the renewed identity: %w", err)
	}
	c, err := enrollment.Connect(&next)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.id, s.client = &next, c
	s.mu.Unlock()
	if expires, err := next.CertNotAfter(); err == nil {
		s.cfg.Log.Info("renewed the client certificate", "not_after", expires)
	}
	return nil
}

// wipe removes the local identity and state after unenrollment.
func (s *Session) wipe() {
	if err := s.cfg.IDStore.Delete(); err != nil {
		s.cfg.Log.Error("deleting the local identity failed", "error", err)
	}
	if err := s.cfg.State.Destroy(); err != nil {
		s.cfg.Log.Error("deleting the local state failed", "error", err)
	}
	s.cfg.Log.Warn("this device was unenrolled; local identity and state removed")
}

func (s *Session) currentClient() *client.Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.client
}

// scriptClient routes the scheduler's calls through the session's current
// client, so a certificate renewal is picked up without the scheduler knowing
// anything about certificates.
type scriptClient struct{ s *Session }

func (c scriptClient) FetchScript(ctx context.Context, id string, version int) (protocol.ScriptVersionResponse, error) {
	return c.s.currentClient().FetchScript(ctx, id, version)
}

func (c scriptClient) ReportScriptRun(ctx context.Context, id string, run protocol.ScriptRun) error {
	return c.s.currentClient().ReportScriptRun(ctx, id, run)
}

// scriptSyncer adapts the script scheduler. It is not called with an empty
// item list: a script that is no longer assigned simply stops running.
type scriptSyncer struct{ s *scripts.Scheduler }

func (a scriptSyncer) Sync(ctx context.Context, items []protocol.Item) error {
	return a.s.Sync(ctx, items)
}
func (scriptSyncer) RunOnEmpty() bool { return false }
func (scriptSyncer) Name() string     { return "assigned scripts" }

// appClient routes the app syncer's calls through the session's current
// client, so a certificate renewal is picked up without the syncer knowing
// anything about certificates.
type appClient struct{ s *Session }

func (c appClient) FetchApp(ctx context.Context, id string, version int) (protocol.AppVersionResponse, error) {
	return c.s.currentClient().FetchApp(ctx, id, version)
}

func (c appClient) ReportAppResult(ctx context.Context, id string, r protocol.AppResult) error {
	return c.s.currentClient().ReportAppResult(ctx, id, r)
}

func (c appClient) DownloadAppPackage(ctx context.Context, id string, version int, sha string, dst io.Writer) error {
	return c.s.currentClient().DownloadAppPackage(ctx, id, version, sha, dst)
}

// appSyncer adapts the app syncer. Like scripts, it is not called with an
// empty item list: an app that is no longer assigned stays installed until
// somebody assigns it with uninstall intent.
type appSyncer struct{ s *apps.Syncer }

func (a appSyncer) Sync(ctx context.Context, items []protocol.Item) error {
	return a.s.Sync(ctx, items)
}
func (appSyncer) RunOnEmpty() bool { return false }
func (appSyncer) Name() string     { return "assigned apps" }

// policySyncer adapts the profile reconciler, which must run on an empty list:
// that is exactly when a profile that has just been unassigned is undone.
type policySyncer struct{ s *policy.Syncer }

func (a policySyncer) Sync(ctx context.Context, items []protocol.Item) error {
	return a.s.Sync(ctx, items)
}
func (policySyncer) RunOnEmpty() bool { return true }
func (policySyncer) Name() string     { return "configuration profiles" }

// policyClient routes the policy engine's calls through the session's current
// client, so a certificate renewal is picked up automatically.
type policyClient struct{ s *Session }

func (c policyClient) FetchProfile(ctx context.Context, id string, version int) (protocol.ProfileVersionResponse, error) {
	return c.s.currentClient().FetchProfile(ctx, id, version)
}

func (c policyClient) ReportProfileStatus(ctx context.Context, id string, status protocol.ProfileStatus) error {
	return c.s.currentClient().ReportProfileStatus(ctx, id, status)
}

// HasRecoveryKey satisfies policy.Escrower through the session's current
// client.
func (c policyClient) HasRecoveryKey(ctx context.Context, volumeID string) (bool, error) {
	return c.s.currentClient().HasRecoveryKey(ctx, volumeID)
}

// EscrowRecoveryKey satisfies policy.Escrower through the session's current
// client.
func (c policyClient) EscrowRecoveryKey(ctx context.Context, volumeID, method, recoveryPassword string) error {
	return c.s.currentClient().EscrowRecoveryKey(ctx, volumeID, method, recoveryPassword)
}

// selfUpdateClient routes the self-update syncer's calls through the
// session's current client, so a certificate renewal is picked up without the
// syncer knowing anything about certificates.
type selfUpdateClient struct{ s *Session }

func (c selfUpdateClient) FetchAgentVersion(ctx context.Context, id string) (protocol.AgentVersionResponse, error) {
	return c.s.currentClient().FetchAgentVersion(ctx, id)
}

func (c selfUpdateClient) DownloadAgentBinary(ctx context.Context, id, sha string, dst io.Writer) error {
	return c.s.currentClient().DownloadAgentBinary(ctx, id, sha, dst)
}

func (c selfUpdateClient) ReportAgentUpdate(ctx context.Context, id string, r protocol.AgentUpdateResult) error {
	return c.s.currentClient().ReportAgentUpdate(ctx, id, r)
}

// selfUpdateSyncer adapts the self-update syncer. It is not called with an
// empty item list: an agent that is no longer assigned a build keeps the one
// it is running, because unassignment is not a downgrade instruction.
type selfUpdateSyncer struct{ s *selfupdate.Syncer }

func (a selfUpdateSyncer) Sync(ctx context.Context, items []protocol.Item) error {
	return a.s.Sync(ctx, items)
}
func (selfUpdateSyncer) RunOnEmpty() bool { return false }
func (selfUpdateSyncer) Name() string     { return "agent self-update" }
