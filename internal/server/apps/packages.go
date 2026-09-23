package apps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/artifacts"
	"retune/internal/server/store"
)

// ErrNoPackage is returned when an app version names an uploaded file the
// server doesn't have.
var ErrNoPackage = errors.New("no uploaded package with that hash")

// PackageGrace is how long an uploaded file may sit unused before it is
// removed: long enough to upload it and then fill in the app form.
const PackageGrace = 24 * time.Hour

const maxCommandLine = 2048

// UploadPackage stores an installer and records who uploaded it. The same
// file uploaded twice is stored once.
func (s *Service) UploadPackage(ctx context.Context, body io.Reader, fileName, actor string) (string, int64, error) {
	if s.Packages.Dir == "" {
		return "", 0, fmt.Errorf("%w: this server has nowhere to keep uploaded packages", ErrBadRequest)
	}
	sha, size, err := s.Packages.Put(body, protocol.MaxPackageBytes)
	if errors.Is(err, artifacts.ErrTooLarge) {
		return "", 0, fmt.Errorf("%w: a package can be at most 2 GiB", ErrBadRequest)
	}
	if err != nil {
		return "", 0, err
	}
	if size == 0 {
		return "", 0, fmt.Errorf("%w: the upload was empty", ErrBadRequest)
	}
	err = s.Store.Q().InsertAudit(ctx, store.AuditEntry{
		Actor: actor, Action: "app_package.uploaded", TargetKind: "app_package", TargetID: sha,
		Details: map[string]any{"file_name": fileName, "size_bytes": size},
	})
	return sha, size, err
}

// OpenPackage returns the file an app version installs.
func (s *Service) OpenPackage(ctx context.Context, appID uuid.UUID, version int) (io.ReadCloser, int64, error) {
	v, err := s.Version(ctx, appID, version)
	if err != nil {
		return nil, 0, err
	}
	if v.Source != protocol.AppSourcePackage {
		return nil, 0, ErrNotFound
	}
	f, size, err := s.Packages.Open(v.FileSHA256)
	if errors.Is(err, artifacts.ErrNotFound) {
		return nil, 0, ErrNoPackage
	}
	return f, size, err
}

// PrunePackages removes uploaded files no app version uses, once they are
// older than PackageGrace, and abandoned partial uploads. It returns how many
// it removed.
func (s *Service) PrunePackages(ctx context.Context, now time.Time) (int64, error) {
	if s.Packages.Dir == "" {
		return 0, nil
	}
	blobs, err := s.Packages.List()
	if err != nil {
		return 0, err
	}
	var removed int64
	for _, b := range blobs {
		if now.Sub(b.ModTime) < PackageGrace {
			continue
		}
		if strings.HasSuffix(b.SHA256, ".part") {
			if err := s.Packages.RemovePart(b.SHA256); err != nil {
				return removed, err
			}
			removed++
			continue
		}
		used, err := s.Store.Q().AppPackageInUse(ctx, b.SHA256)
		if err != nil {
			return removed, err
		}
		if used {
			continue
		}
		if err := s.Packages.Remove(b.SHA256); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// validatePackage checks the package half of a new app version and fills in
// defaults. It touches the file, so the pruner's grace period restarts and
// it can't remove a file a version is about to name.
func (s *Service) validatePackage(in *NewApp) (int64, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrBadRequest, fmt.Sprintf(format, a...))
	}
	if in.PackageID != "" || in.PinnedVersion != "" {
		return 0, bad("an uploaded package has no winget package id or pinned version")
	}
	switch in.InstallerType {
	case protocol.InstallerMSI, protocol.InstallerEXE:
	default:
		return 0, bad("installer_type must be %q or %q", protocol.InstallerMSI, protocol.InstallerEXE)
	}
	name := strings.TrimSpace(in.FileName)
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\:*?"<>|`) || len(name) > 255 {
		return 0, bad("file_name must be a plain file name, such as setup.msi")
	}
	if !strings.EqualFold(filepath.Ext(name), "."+in.InstallerType) {
		return 0, bad("an %s package's file name must end in .%s", in.InstallerType, in.InstallerType)
	}
	in.FileName = name
	for _, cmd := range []struct{ field, value string }{
		{"install_args", in.InstallArgs}, {"uninstall_command", in.UninstallCommand},
	} {
		if len(cmd.value) > maxCommandLine || strings.ContainsAny(cmd.value, "\r\n\x00") {
			return 0, bad("%s must be one line of at most %d characters", cmd.field, maxCommandLine)
		}
	}
	if in.Detection == nil {
		return 0, bad("an uploaded package needs a detection rule")
	}
	if err := in.Detection.Validate(); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	if len(in.SuccessExitCodes) == 0 {
		in.SuccessExitCodes = protocol.DefaultSuccessExitCodes()
	}
	if len(in.SuccessExitCodes) > 20 {
		return 0, bad("at most 20 success exit codes")
	}
	for _, c := range in.SuccessExitCodes {
		if c < math.MinInt32 || c > math.MaxInt32 {
			return 0, bad("exit code %d is out of range", c)
		}
	}
	if s.Packages.Dir == "" {
		return 0, bad("this server has nowhere to keep uploaded packages")
	}
	in.FileSHA256 = strings.ToLower(strings.TrimSpace(in.FileSHA256))
	size, ok, err := s.Packages.Exists(in.FileSHA256)
	if errors.Is(err, artifacts.ErrBadHash) {
		return 0, bad("file_sha256 must be the hash an upload returned")
	}
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("%w: %w; upload it again", ErrBadRequest, ErrNoPackage)
	}
	if err := s.Packages.Touch(in.FileSHA256, s.now()); err != nil {
		return 0, err
	}
	return size, nil
}

// packageHash identifies a package version's definition, the way Hash does a
// winget one.
func packageHash(v store.AppVersion) string {
	b, _ := json.Marshal([]any{
		v.InstallerType, v.FileName, v.FileSHA256, v.InstallArgs, v.UninstallCommand,
		v.SuccessExitCodes, v.Detection, v.UninstallPrevious,
	})
	sum := sha256.Sum256(append([]byte("package\x00"), b...))
	return hex.EncodeToString(sum[:])
}
