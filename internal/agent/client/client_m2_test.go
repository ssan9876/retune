package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"retune/internal/pki"
	"retune/internal/protocol"
)

func TestM2Calls(t *testing.T) {
	ctx := context.Background()
	var gotMethod, gotPath string
	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/agent/v1/inventory":
			_ = json.NewEncoder(w).Encode(protocol.InventoryResponse{Hash: "h1"})
		case "/api/agent/v1/renew":
			_ = json.NewEncoder(w).Encode(protocol.RenewResponse{CertPEM: "new-cert"})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL, pki.Fingerprint(srv.Certificate().Raw), nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.PutInventory(ctx, protocol.Inventory{Hostname: "PC-1"})
	if err != nil || resp.Hash != "h1" {
		t.Fatalf("PutInventory = %+v, err = %v", resp, err)
	}
	if gotMethod != http.MethodPut || gotPath != "/api/agent/v1/inventory" {
		t.Fatalf("inventory request = %s %s", gotMethod, gotPath)
	}

	if err := c.StartCommand(ctx, "cmd-1"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/agent/v1/commands/cmd-1/start" {
		t.Fatalf("start request = %s %s", gotMethod, gotPath)
	}

	result := protocol.CommandResult{Status: protocol.ResultSucceeded, Stdout: "out"}
	if err := c.SubmitResult(ctx, "cmd-1", result); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/agent/v1/commands/cmd-1/result" {
		t.Fatalf("result path = %s", gotPath)
	}
	var sent protocol.CommandResult
	if err := json.Unmarshal(gotBody, &sent); err != nil || sent.Stdout != "out" {
		t.Fatalf("result body = %s, err = %v", gotBody, err)
	}

	renewed, err := c.Renew(ctx, protocol.RenewRequest{CSRPEM: "csr"})
	if err != nil || renewed.CertPEM != "new-cert" {
		t.Fatalf("Renew = %+v, err = %v", renewed, err)
	}
}
