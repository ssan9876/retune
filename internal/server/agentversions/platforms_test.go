package agentversions_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"

	"retune/internal/protocol"
	"retune/internal/server/agentversions"
	"retune/internal/server/store/storetest"
)

// upload sends one platform's build of version with body as its bytes.
func upload(t *testing.T, svc *agentversions.Service, in agentversions.NewVersion, body string) error {
	t.Helper()
	_, err := svc.Upload(context.Background(), in, strings.NewReader(body))
	return err
}

func readAll(t *testing.T, r io.ReadCloser) string {
	t.Helper()
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// One version, several platforms: the first build creates the version and
// each further one joins it, and every device is handed its own.
func TestUploadBuildsForSeveralPlatforms(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)

	win := signed(priv, "2.0.0", "windows bytes", "ops")
	if err := upload(t, svc, win, "windows bytes"); err != nil {
		t.Fatal(err)
	}
	mac := signed(priv, "2.0.0", "mac bytes", "ops")
	mac.Platform = protocol.PlatformDarwinUniversal
	if err := upload(t, svc, mac, "mac bytes"); err != nil {
		t.Fatalf("a second platform should join the version: %v", err)
	}
	linux := signed(priv, "2.0.0", "linux bytes", "ops")
	linux.Platform = protocol.PlatformLinuxARM64
	if err := upload(t, svc, linux, "linux bytes"); err != nil {
		t.Fatal(err)
	}

	v, err := st.Q().GetAgentVersionByVersion(ctx, "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	builds, err := svc.Builds(ctx, []uuid.UUID{v.ID})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(builds[v.ID]); got != 3 {
		t.Fatalf("want 3 builds, got %d", got)
	}

	for platform, want := range map[string]string{
		"windows-amd64": "windows bytes",
		"darwin-arm64":  "mac bytes", // the universal build serves both Macs
		"darwin-amd64":  "mac bytes",
		"linux-arm64":   "linux bytes",
	} {
		r, _, err := svc.OpenBuild(ctx, v.ID, platform)
		if err != nil {
			t.Fatalf("%s: %v", platform, err)
		}
		if got := readAll(t, r); got != want {
			t.Errorf("%s got %q, want %q", platform, got, want)
		}
	}
	// A platform the version was not built for has nothing to run.
	if _, _, err := svc.BuildFor(ctx, v.ID, protocol.PlatformLinuxAMD64); !errors.Is(err, agentversions.ErrNoBuild) {
		t.Errorf("want ErrNoBuild for linux-amd64, got %v", err)
	}
	if _, _, err := svc.BuildFor(ctx, v.ID, ""); !errors.Is(err, agentversions.ErrNoBuild) {
		t.Errorf("want ErrNoBuild for an unknown platform, got %v", err)
	}
}

// A platform-specific build is preferred to a universal one.
func TestBuildForPrefersTheExactPlatform(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)
	for platform, body := range map[string]string{
		protocol.PlatformDarwinUniversal: "universal",
		protocol.PlatformDarwinARM64:     "arm64 only",
	} {
		in := signed(priv, "3.0.0", body, "ops")
		in.Platform = platform
		if err := upload(t, svc, in, body); err != nil {
			t.Fatal(err)
		}
	}
	v, _ := st.Q().GetAgentVersionByVersion(ctx, "3.0.0")
	_, b, err := svc.BuildFor(ctx, v.ID, protocol.PlatformDarwinARM64)
	if err != nil || b.Platform != protocol.PlatformDarwinARM64 {
		t.Fatalf("want the arm64 build, got %+v %v", b, err)
	}
	_, b, _ = svc.BuildFor(ctx, v.ID, protocol.PlatformDarwinAMD64)
	if b.Platform != protocol.PlatformDarwinUniversal {
		t.Fatalf("an Intel Mac should get the universal build, got %q", b.Platform)
	}
}

// The same platform twice is refused, and a refused upload for one platform
// never touches another platform's bytes.
func TestUploadRefusesADuplicatePlatformAndKeepsTheOthers(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc, priv := service(t, st)
	if err := upload(t, svc, signed(priv, "4.0.0", "first", "ops"), "first"); err != nil {
		t.Fatal(err)
	}
	if err := upload(t, svc, signed(priv, "4.0.0", "again", "ops"), "again"); !errors.Is(err, agentversions.ErrVersionTaken) {
		t.Fatalf("want ErrVersionTaken for a second windows build, got %v", err)
	}
	// A Mac build whose signature is over other bytes is refused after its
	// bytes landed; cleaning up must remove only them.
	bad := signed(priv, "4.0.0", "what was signed", "ops")
	bad.Platform = protocol.PlatformDarwinARM64
	if err := upload(t, svc, bad, "something else"); !errors.Is(err, agentversions.ErrBadRequest) {
		t.Fatalf("want ErrBadRequest, got %v", err)
	}
	v, _ := st.Q().GetAgentVersionByVersion(ctx, "4.0.0")
	r, _, err := svc.OpenBuild(ctx, v.ID, protocol.PlatformWindowsAMD64)
	if err != nil {
		t.Fatalf("the windows build must survive a refused mac upload: %v", err)
	}
	if got := readAll(t, r); got != "first" {
		t.Fatalf("windows build is %q", got)
	}
	if _, _, err := svc.BuildFor(ctx, v.ID, protocol.PlatformDarwinARM64); !errors.Is(err, agentversions.ErrNoBuild) {
		t.Errorf("the refused mac build must not be recorded: %v", err)
	}
}

// An unknown platform is the caller's mistake.
func TestUploadRejectsAnUnknownPlatform(t *testing.T) {
	st := storetest.New(t)
	svc, priv := service(t, st)
	in := signed(priv, "5.0.0", "x", "ops")
	in.Platform = "freebsd-amd64"
	if err := upload(t, svc, in, "x"); !errors.Is(err, agentversions.ErrBadRequest) {
		t.Fatalf("want ErrBadRequest, got %v", err)
	}
}

// A build stored before platforms existed sits directly in its version's
// directory; it is still served, as the windows-amd64 build the migration
// recorded it as.
func TestLegacyWindowsBuildIsStillServed(t *testing.T) {
	st := storetest.New(t)
	svc, _ := service(t, st)
	if _, _, err := svc.Artifacts.Put("1.0.0", strings.NewReader("legacy"), 1<<20); err != nil {
		t.Fatal(err)
	}
	r, _, err := svc.Artifacts.OpenBuild("1.0.0", protocol.PlatformWindowsAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, r); got != "legacy" {
		t.Fatalf("got %q", got)
	}
	if _, _, err := svc.Artifacts.OpenBuild("1.0.0", protocol.PlatformDarwinARM64); err == nil {
		t.Fatal("the legacy build is Windows only")
	}
}
