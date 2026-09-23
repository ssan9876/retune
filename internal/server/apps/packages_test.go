package apps_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"retune/internal/protocol"
	"retune/internal/server/apps"
	"retune/internal/server/artifacts"
	"retune/internal/server/store"
	"retune/internal/server/store/storetest"
)

const productCode = "{23170F69-40C1-2702-2600-000001000000}"

func packageService(t *testing.T, st *store.Store) *apps.Service {
	t.Helper()
	return &apps.Service{Store: st, Packages: artifacts.Blobs{Dir: filepath.Join(t.TempDir(), "pkgs")}}
}

func upload(t *testing.T, svc *apps.Service, body string) string {
	t.Helper()
	sha, _, err := svc.UploadPackage(context.Background(), strings.NewReader(body), "setup.msi", "ops")
	if err != nil {
		t.Fatal(err)
	}
	return sha
}

func msiApp(name, sha string) apps.NewApp {
	return apps.NewApp{
		Name: name, Actor: "ops", Source: protocol.AppSourcePackage, InstallerType: protocol.InstallerMSI,
		FileSHA256: sha, FileName: "Contoso.msi",
		Detection: &protocol.DetectionRule{Type: protocol.DetectMSIProductCode, ProductCode: productCode},
	}
}

func TestPackageAppVersions(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := packageService(t, st)
	sha := upload(t, svc, "version one")

	a, err := svc.Create(ctx, msiApp("Contoso", sha))
	if err != nil {
		t.Fatal(err)
	}
	v, err := svc.Version(ctx, a.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if v.Source != protocol.AppSourcePackage || v.FileSHA256 != sha || v.FileSize != int64(len("version one")) ||
		v.PackageID != "" || len(v.SuccessExitCodes) != 3 {
		t.Fatalf("version 1 = %+v", v)
	}

	// Saving the same definition again, or renaming, is not a new version.
	same := msiApp("Contoso renamed", sha)
	if a, err = svc.Update(ctx, a.ID, same); err != nil || a.CurrentVersion != 1 {
		t.Fatalf("unchanged update = %d, %v", a.CurrentVersion, err)
	}
	// A new file is.
	next := msiApp("Contoso renamed", upload(t, svc, "version two"))
	next.UninstallPrevious = true
	if a, err = svc.Update(ctx, a.ID, next); err != nil || a.CurrentVersion != 2 {
		t.Fatalf("new file = %d, %v", a.CurrentVersion, err)
	}
	if v, _ := svc.Version(ctx, a.ID, 2); !v.UninstallPrevious {
		t.Error("uninstall_previous wasn't kept")
	}

	f, size, err := svc.OpenPackage(ctx, a.ID, 1)
	if err != nil || size != int64(len("version one")) {
		t.Fatalf("OpenPackage = %d, %v", size, err)
	}
	f.Close()

	// A winget app has no package to open.
	w, err := svc.Create(ctx, apps.NewApp{Name: "7-Zip", PackageID: "7zip.7zip", Actor: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.OpenPackage(ctx, w.ID, 1); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("OpenPackage on a winget app = %v", err)
	}
}

func TestPackageAppValidation(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := packageService(t, st)
	sha := upload(t, svc, "an msi")

	cases := map[string]func(*apps.NewApp){
		"no installer type":      func(in *apps.NewApp) { in.InstallerType = "" },
		"unknown installer type": func(in *apps.NewApp) { in.InstallerType = "msix" },
		"no file name":           func(in *apps.NewApp) { in.FileName = "" },
		"a path for a name":      func(in *apps.NewApp) { in.FileName = `..\Contoso.msi` },
		"wrong extension":        func(in *apps.NewApp) { in.FileName = "Contoso.exe" },
		"no detection":           func(in *apps.NewApp) { in.Detection = nil },
		"bad detection":          func(in *apps.NewApp) { in.Detection = &protocol.DetectionRule{Type: "wmi"} },
		"never uploaded": func(in *apps.NewApp) {
			in.FileSHA256 = strings.Repeat("a", 64)
		},
		"not a hash":             func(in *apps.NewApp) { in.FileSHA256 = "../../etc/passwd" },
		"a winget id too":        func(in *apps.NewApp) { in.PackageID = "7zip.7zip" },
		"multi-line arguments":   func(in *apps.NewApp) { in.InstallArgs = "/qn\r\nevil" },
		"unknown source":         func(in *apps.NewApp) { in.Source = "chocolatey" },
		"too many success codes": func(in *apps.NewApp) { in.SuccessExitCodes = make([]int, 21) },
	}
	for name, mutate := range cases {
		in := msiApp("App "+name, sha)
		mutate(&in)
		if _, err := svc.Create(ctx, in); !errors.Is(err, apps.ErrBadRequest) {
			t.Errorf("%s: err = %v, want ErrBadRequest", name, err)
		}
	}

	// Package settings on a winget app are refused, not silently dropped.
	if _, err := svc.Create(ctx, apps.NewApp{
		Name: "7-Zip", PackageID: "7zip.7zip", Actor: "ops", InstallerType: protocol.InstallerMSI,
	}); !errors.Is(err, apps.ErrBadRequest) {
		t.Errorf("a winget app with an installer type = %v", err)
	}

	// With nowhere to keep uploads, packages are refused outright.
	plain := &apps.Service{Store: st}
	if _, _, err := plain.UploadPackage(ctx, strings.NewReader("x"), "a.msi", "ops"); !errors.Is(err, apps.ErrBadRequest) {
		t.Errorf("upload with no directory = %v", err)
	}
	if _, _, err := svc.UploadPackage(ctx, strings.NewReader(""), "a.msi", "ops"); !errors.Is(err, apps.ErrBadRequest) {
		t.Errorf("an empty upload = %v", err)
	}
}

func TestPrunePackages(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := packageService(t, st)
	used := upload(t, svc, "in use")
	unused := upload(t, svc, "never used")
	fresh := upload(t, svc, "just uploaded")
	if _, err := svc.Create(ctx, msiApp("Contoso", used)); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * apps.PackageGrace)
	for _, sha := range []string{used, unused} {
		if err := svc.Packages.Touch(sha, old); err != nil {
			t.Fatal(err)
		}
	}

	n, err := svc.PrunePackages(ctx, time.Now())
	if err != nil || n != 1 {
		t.Fatalf("PrunePackages = %d, %v; want 1", n, err)
	}
	for sha, want := range map[string]bool{used: true, unused: false, fresh: true} {
		if _, ok, _ := svc.Packages.Exists(sha); ok != want {
			t.Errorf("%s kept = %v, want %v", sha[:8], ok, want)
		}
	}

	// Once its app is deleted, a package is fair game too.
	a, _, _ := svc.List(ctx, store.Page{})
	if err := svc.Delete(ctx, a[0].ID, "ops"); err != nil {
		t.Fatal(err)
	}
	if n, err := svc.PrunePackages(ctx, time.Now()); err != nil || n != 1 {
		t.Fatalf("after deleting the app = %d, %v", n, err)
	}
}
