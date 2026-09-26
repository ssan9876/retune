package releasefeed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/release"
	"retune/internal/server/agentversions"
	"retune/internal/server/store"
	"retune/internal/server/sweeper"
)

// Actor is who the audit log says imported a release.
const Actor = "system:release-feed"

// LockID is the feed's advisory lock, shared by the sweeper job and "Check
// now", so two replicas - or a click and a tick - never import at once.
const LockID = 5274012

// The files the feed reads, and how large each may be.
const (
	ManifestAsset    = "release.json"
	signatureSuffix  = ".sig"
	maxManifestBytes = 1 << 20
	maxSigBytes      = 16 << 10
)

var (
	// ErrBusy is "Check now" while a check is already running.
	ErrBusy = errors.New("a release check is already running")
	// ErrNoKeys is a feed with nothing to verify releases against.
	ErrNoKeys = errors.New("AGENT_RELEASE_KEYS is not set, so no release can be verified")
)

// Service finds, verifies and imports releases.
type Service struct {
	Store  *store.Store
	Source Source
	// Keys are AGENT_RELEASE_KEYS: a release's manifest must be signed by one.
	Keys   []release.PublicKey
	Agents *agentversions.Service
	// Rollout, when set, is told about every agent build imported.
	Rollout *Rollout
	// AllowPrerelease also takes prereleases; otherwise they are ignored.
	AllowPrerelease bool
	Now             func() time.Time
	Log             *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Job is the feed's sweeper job.
func (s *Service) Job(interval time.Duration) sweeper.Job {
	return sweeper.Job{
		Name: "releases.check", LockID: LockID, Interval: interval,
		Run: func(ctx context.Context, _ *store.Queries, _ time.Time) (int64, error) {
			return s.Poll(ctx)
		},
	}
}

// CheckNow runs one check at once, unless one is already running.
func (s *Service) CheckNow(ctx context.Context) error {
	var err error
	ran, lockErr := s.Store.WithAdvisoryLock(ctx, LockID, func(*store.Queries) error {
		_, err = s.Poll(ctx)
		return nil
	})
	if lockErr != nil {
		return lockErr
	}
	if !ran {
		return ErrBusy
	}
	return err
}

// Poll checks the feed once. It looks only at the newest release it is
// allowed to take: one newer than every release already recorded is verified
// and recorded, and a recorded release whose agent build is not yet imported
// is imported. Older releases are never looked at - the feed only moves
// forward - and a failure is recorded where the console shows it.
func (s *Service) Poll(ctx context.Context) (int64, error) {
	n, err := s.poll(ctx)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if serr := s.Store.Q().SetReleaseFeedState(ctx, s.now(), msg); serr != nil && err == nil {
		err = serr
	}
	return n, err
}

func (s *Service) poll(ctx context.Context) (int64, error) {
	if len(s.Keys) == 0 {
		return 0, ErrNoKeys
	}
	candidates, err := s.Source.List(ctx)
	if err != nil {
		return 0, err
	}
	target, ok := s.newest(candidates)
	if !ok {
		return 0, nil
	}
	q := s.Store.Q()
	rel, err := q.GetReleaseByVersion(ctx, target.Version)
	var changed int64
	switch {
	case errors.Is(err, store.ErrNotFound):
		known, err := q.ListReleases(ctx)
		if err != nil {
			return 0, err
		}
		for _, k := range known {
			if !release.Newer(target.Version, k.Version) {
				// Something newer is already recorded, which the list
				// no longer shows: never go backwards.
				return 0, nil
			}
		}
		if rel, err = s.record(ctx, target); err != nil {
			return 0, err
		}
		changed++
	case err != nil:
		return 0, err
	}
	if rel.AgentVersionID != nil {
		return changed, nil
	}
	imported, err := s.importAgent(ctx, rel, target)
	if err != nil {
		if serr := q.SetReleaseImport(ctx, rel.ID, nil, err.Error()); serr != nil {
			s.log().Warn("record release import failure", "error", serr)
		}
		return changed, fmt.Errorf("import the agent from %s: %w", rel.Version, err)
	}
	if imported {
		changed++
	}
	return changed, nil
}

// newest is the newest candidate the feed may take.
func (s *Service) newest(candidates []Candidate) (Candidate, bool) {
	var ok []Candidate
	for _, c := range candidates {
		if c.Draft || (c.Prerelease && !s.AllowPrerelease) {
			continue
		}
		if _, err := release.ParseVersion(c.Version); err != nil {
			continue
		}
		ok = append(ok, c)
	}
	if len(ok) == 0 {
		return Candidate{}, false
	}
	sort.Slice(ok, func(i, j int) bool { return release.Newer(ok[i].Version, ok[j].Version) })
	return ok[0], true
}

// fetchManifest downloads a release's manifest and signature and verifies
// them. Only a verified manifest is returned.
func (s *Service) fetchManifest(ctx context.Context, c Candidate) (raw, sigRaw []byte, m release.ReleaseManifest, sig release.Signature, err error) {
	manifestURL, sigURL := c.Assets[ManifestAsset], c.Assets[ManifestAsset+signatureSuffix]
	if manifestURL == "" || sigURL == "" {
		return nil, nil, m, sig, fmt.Errorf("release %s publishes no signed %s", c.Version, ManifestAsset)
	}
	if raw, err = readAll(ctx, s.Source, manifestURL, maxManifestBytes); err != nil {
		return nil, nil, m, sig, err
	}
	if sigRaw, err = readAll(ctx, s.Source, sigURL, maxSigBytes); err != nil {
		return nil, nil, m, sig, err
	}
	if sig, err = release.DecodeSidecar(sigRaw); err != nil {
		return nil, nil, m, sig, fmt.Errorf("%s%s: %w", ManifestAsset, signatureSuffix, err)
	}
	if m, err = release.VerifyReleaseManifest(s.Keys, raw, sig); err != nil {
		return nil, nil, m, sig, fmt.Errorf("release %s: %s did not verify: %w", c.Version, ManifestAsset, err)
	}
	if m.Version != c.Version {
		return nil, nil, m, sig, fmt.Errorf("release %s: its manifest is for %s", c.Version, m.Version)
	}
	if m.Prerelease && !s.AllowPrerelease {
		return nil, nil, m, sig, fmt.Errorf("release %s: its manifest says it is a prerelease", c.Version)
	}
	return raw, sigRaw, m, sig, nil
}

// record verifies a release and records it.
func (s *Service) record(ctx context.Context, c Candidate) (store.Release, error) {
	raw, sigRaw, m, sig, err := s.fetchManifest(ctx, c)
	if err != nil {
		return store.Release{}, err
	}
	rel := store.Release{
		ID: uuid.Must(uuid.NewV7()), Version: m.Version, Prerelease: m.Prerelease, PublishedAt: m.PublishedAt,
		Notes: m.Notes, Manifest: raw, Signature: sigRaw, KeyID: sig.KeyID, VerifiedAt: s.now(),
	}
	err = s.Store.InTx(ctx, func(q *store.Queries) error {
		created, err := q.CreateRelease(ctx, rel)
		if err != nil || !created {
			return err
		}
		return q.InsertAudit(ctx, store.AuditEntry{
			Actor: Actor, Action: "release.verified", TargetKind: "release", TargetID: rel.ID.String(),
			Details: map[string]any{"version": rel.Version, "key_id": rel.KeyID, "prerelease": rel.Prerelease},
		})
	})
	if err != nil {
		return store.Release{}, err
	}
	s.log().Info("verified a new release", "version", rel.Version, "key_id", rel.KeyID)
	return s.Store.Q().GetReleaseByVersion(ctx, rel.Version)
}

// importAgent downloads every agent build the release carries - one per
// platform - and adds each to one agent version the way an upload would. Each
// build's hash must match the manifest, its signature must be the release
// key's over that hash and this version, and the upload path checks both again
// against the bytes themselves. Only once every build is in is the release
// marked imported and the version handed to the rollout; a build that failed
// is tried again next time, and the ones already in are left alone.
func (s *Service) importAgent(ctx context.Context, rel store.Release, c Candidate) (bool, error) {
	var sig release.Signature
	if err := json.Unmarshal(rel.Signature, &sig); err != nil {
		return false, err
	}
	// The stored manifest is verified again rather than trusted from when it
	// was recorded.
	m, err := release.VerifyReleaseManifest(s.Keys, rel.Manifest, sig)
	if err != nil {
		return false, fmt.Errorf("the recorded manifest no longer verifies: %w", err)
	}
	builds := agentBuilds(m)
	if len(builds) == 0 {
		return false, fmt.Errorf("release %s has no agent builds", rel.Version)
	}
	var v store.AgentVersion
	imported := false
	var errs []error
	for _, b := range builds {
		got, did, err := s.importBuild(ctx, rel, c, m, b)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", b.platform, err))
			continue
		}
		v, imported = got, imported || did
	}
	if len(errs) > 0 {
		return imported, errors.Join(errs...)
	}
	if err := s.Store.Q().SetReleaseImport(ctx, rel.ID, &v.ID, ""); err != nil {
		return imported, err
	}
	if imported {
		s.log().Info("imported the agent from a release", "version", v.Version, "builds", len(builds))
	}
	if s.Rollout != nil {
		if err := s.Rollout.Start(ctx, v); err != nil {
			// The version is in; the rollout is retried by its own job.
			s.log().Warn("start the automatic rollout", "version", v.Version, "error", err)
		}
	}
	return imported, nil
}

// agentBuild is one of a release's agent builds and the platform it is for.
type agentBuild struct {
	asset    release.Asset
	platform string
}

// agentBuilds lists a release's bare agent builds by platform, in the order
// protocol.Platforms gives. The installers are not builds a device swaps in.
func agentBuilds(m release.ReleaseManifest) []agentBuild {
	var out []agentBuild
	for _, platform := range protocol.Platforms {
		goos, goarch, _ := strings.Cut(platform, "-")
		if a, ok := m.Find(release.AssetAgent, goos, goarch); ok {
			out = append(out, agentBuild{asset: a, platform: platform})
		}
	}
	return out
}

func (s *Service) importBuild(ctx context.Context, rel store.Release, c Candidate, m release.ReleaseManifest, b agentBuild) (store.AgentVersion, bool, error) {
	sigAsset, ok := m.Named(b.asset.Name + signatureSuffix)
	if !ok {
		return store.AgentVersion{}, false, fmt.Errorf("the release has no %s%s", b.asset.Name, signatureSuffix)
	}
	binURL, sigURL := c.Assets[b.asset.Name], c.Assets[sigAsset.Name]
	if binURL == "" || sigURL == "" {
		return store.AgentVersion{}, false, fmt.Errorf("the feed lists no download for %s", b.asset.Name)
	}
	sigRaw, err := readAll(ctx, s.Source, sigURL, maxSigBytes)
	if err != nil {
		return store.AgentVersion{}, false, err
	}
	if got := sha256Hex(sigRaw); !strings.EqualFold(got, sigAsset.SHA256) {
		return store.AgentVersion{}, false, fmt.Errorf("%s hashes to %s, not the manifest's %s", sigAsset.Name, got, sigAsset.SHA256)
	}
	buildSig, err := release.DecodeSidecar(sigRaw)
	if err != nil {
		return store.AgentVersion{}, false, err
	}
	if buildSig.Version != rel.Version || !strings.EqualFold(buildSig.SHA256, b.asset.SHA256) {
		return store.AgentVersion{}, false, fmt.Errorf("%s is for %s %s, not %s %s", sigAsset.Name,
			buildSig.Version, buildSig.SHA256, rel.Version, b.asset.SHA256)
	}
	body, err := s.Source.Open(ctx, binURL)
	if err != nil {
		return store.AgentVersion{}, false, err
	}
	defer body.Close()
	return s.Agents.Import(ctx, b.platform, buildSig, "Imported from release "+rel.Version+".", Actor, body)
}

// Latest is the newest verified release, with its manifest verified again
// now. This is what a server updating itself reads: the image digest and the
// server binaries' hashes are in the manifest.
func (s *Service) Latest(ctx context.Context) (store.Release, release.ReleaseManifest, error) {
	rels, err := s.Store.Q().ListReleases(ctx)
	if err != nil {
		return store.Release{}, release.ReleaseManifest{}, err
	}
	if len(rels) == 0 {
		return store.Release{}, release.ReleaseManifest{}, store.ErrNotFound
	}
	sort.Slice(rels, func(i, j int) bool { return release.Newer(rels[i].Version, rels[j].Version) })
	rel := rels[0]
	var sig release.Signature
	if err := json.Unmarshal(rel.Signature, &sig); err != nil {
		return store.Release{}, release.ReleaseManifest{}, err
	}
	m, err := release.VerifyReleaseManifest(s.Keys, rel.Manifest, sig)
	if err != nil {
		return store.Release{}, release.ReleaseManifest{}, err
	}
	return rel, m, nil
}
