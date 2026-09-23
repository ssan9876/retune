package app_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"testing"

	"retune/internal/protocol"
	"retune/internal/server/store"
)

// TestUploadedPackageReachesTheAgent: an installer is uploaded, an app is
// made from it, and only a device it is assigned to can read its definition
// and download it.
func TestUploadedPackageReachesTheAgent(t *testing.T) {
	a, srv := newTestApp(t)
	admin := signedIn(t, a, srv, store.RoleAdmin)
	_, agent := enrollDevice(t, a, srv, "DESKTOP-PKG")
	installer := []byte("pretend this is an MSI")
	sum := sha256.Sum256(installer)
	wantSHA := hex.EncodeToString(sum[:])

	status, body := admin.doRaw(http.MethodPost, "/app-packages?file_name=Contoso.msi",
		"application/octet-stream", bytes.NewReader(installer))
	if status != http.StatusCreated {
		t.Fatalf("upload: %d %s", status, body)
	}
	up := decodeJSON[struct {
		SHA256 string `json:"file_sha256"`
		Size   int64  `json:"size_bytes"`
	}](t, body)
	if up.SHA256 != wantSHA || up.Size != int64(len(installer)) {
		t.Fatalf("upload = %+v", up)
	}

	status, body = admin.do(http.MethodPost, "/apps", map[string]any{
		"name": "Contoso", "source": "package", "installer_type": "msi",
		"file_sha256": up.SHA256, "file_name": "Contoso.msi", "install_args": "ALLUSERS=1",
		"detection": map[string]any{"type": "msi_product_code", "product_code": "{23170F69-40C1-2702-2600-000001000000}"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	created := decodeJSON[struct {
		ID               string                  `json:"id"`
		Source           string                  `json:"source"`
		FileSize         int64                   `json:"file_size"`
		SuccessExitCodes []int                   `json:"success_exit_codes"`
		Detection        *protocol.DetectionRule `json:"detection"`
	}](t, body)
	if created.Source != "package" || created.FileSize != int64(len(installer)) ||
		len(created.SuccessExitCodes) != 3 || created.Detection == nil {
		t.Fatalf("created = %+v", created)
	}

	defURL := srv.URL + "/api/agent/v1/apps/" + created.ID + "/versions/1"
	// Not assigned yet: the device can see neither the definition nor the file.
	if status, _ := send(t, agent, http.MethodGet, defURL, nil); status != http.StatusNotFound {
		t.Fatalf("unassigned definition: %d", status)
	}
	if res, err := agent.Get(defURL + "/package"); err != nil || res.StatusCode != http.StatusNotFound {
		t.Fatalf("unassigned download: %v %v", res, err)
	} else {
		res.Body.Close()
	}

	admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "app", "item_id": created.ID,
		"group_id": "00000000-0000-0000-0000-000000000002", "mode": "include",
	})
	status, body = send(t, agent, http.MethodGet, defURL, nil)
	if status != http.StatusOK {
		t.Fatalf("definition: %d %s", status, body)
	}
	def := decodeJSON[protocol.AppVersionResponse](t, body)
	if !def.IsPackage() || def.FileSHA256 != wantSHA || def.InstallerType != "msi" || def.InstallArgs != "ALLUSERS=1" ||
		def.Detection == nil || def.Detection.ProductCode == "" || def.FileName != "Contoso.msi" {
		t.Fatalf("definition = %+v", def)
	}

	res, err := agent.Get(defURL + "/package")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !bytes.Equal(got, installer) {
		t.Fatalf("download: %d, %d bytes", res.StatusCode, len(got))
	}

	// A winget app has no package to download.
	_, body = admin.do(http.MethodPost, "/apps", map[string]any{"name": "7-Zip", "package_id": "7zip.7zip"})
	winget := decodeJSON[appResp](t, body)
	admin.do(http.MethodPost, "/assignments", map[string]any{
		"item_kind": "app", "item_id": winget.ID,
		"group_id": "00000000-0000-0000-0000-000000000002", "mode": "include",
	})
	if res, err := agent.Get(srv.URL + "/api/agent/v1/apps/" + winget.ID + "/versions/1/package"); err != nil ||
		res.StatusCode != http.StatusNotFound {
		t.Fatalf("winget download: %v %v", res, err)
	} else {
		res.Body.Close()
	}

	// Read-only admins can't upload.
	ro := signedIn(t, a, srv, store.RoleReadOnly)
	if status, _ := ro.doRaw(http.MethodPost, "/app-packages?file_name=x.msi", "application/octet-stream",
		bytes.NewReader([]byte("x"))); status != http.StatusForbidden {
		t.Fatalf("read-only upload: %d", status)
	}
}
