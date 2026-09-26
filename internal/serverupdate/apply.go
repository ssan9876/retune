package serverupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"retune/internal/release"
)

// ApplyStaged carries out the update the server staged in dir, if there is
// one: what `retune-server update-apply` does when systemd starts it. It
// verifies the release against keys itself - the server only chose which
// version - and the staged binary against the manifest's hash, then swaps it
// in with env. It reports false when there was nothing to do.
func ApplyStaged(ctx context.Context, dir string, env *Binary, keys []release.PublicKey, log *slog.Logger) (State, bool, error) {
	reqPath := filepath.Join(dir, RequestFile)
	b, err := os.ReadFile(reqPath)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	// The request is consumed whatever happens next, so a bad one is not
	// retried for ever by the path unit.
	defer os.Remove(reqPath)
	var req ApplyRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return State{}, true, fmt.Errorf("%s: %w", RequestFile, err)
	}
	staged, err := filepath.Abs(req.Staged)
	if err != nil {
		return State{}, true, err
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return State{}, true, err
	}
	if !strings.HasPrefix(staged, root+string(filepath.Separator)) {
		return State{}, true, fmt.Errorf("the staged binary %s is outside %s", staged, root)
	}
	env.StagedPath = staged
	states := FileStore{Path: filepath.Join(dir, StateFile)}
	u := &Updater{Env: env, Fetch: DirFetcher{Dir: dir}, Keys: keys, Save: states.Save, Now: time.Now, Log: log}
	return u.Run(ctx, req.Request), true, nil
}
