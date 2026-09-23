package adminapi

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var updateOpenAPI = flag.Bool("update-openapi", false, "rewrite docs/openapi.json")

var openAPIPath = filepath.Join("..", "..", "..", "docs", "openapi.json")

// TestOpenAPIDocument: every route is described, the committed document is
// the generated one, and it is internally consistent. After changing a route
// or a type it describes, run:
//
//	go test ./internal/server/adminapi -run TestOpenAPIDocument -update-openapi
func TestOpenAPIDocument(t *testing.T) {
	h := &Handler{}
	got, err := h.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateOpenAPI {
		if err := os.WriteFile(openAPIPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(openAPIPath)
	if err != nil {
		t.Fatalf("%v (generate it with -update-openapi)", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
		t.Fatal("docs/openapi.json is out of date: go test ./internal/server/adminapi -run TestOpenAPIDocument -update-openapi")
	}

	var doc struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	ops := 0
	ids := map[string]bool{}
	for path, methods := range doc.Paths {
		ops += len(methods)
		for method, raw := range methods {
			var op struct {
				OperationID string `json:"operationId"`
			}
			if err := json.Unmarshal(raw, &op); err != nil {
				t.Fatal(err)
			}
			if ids[op.OperationID] {
				t.Errorf("%s %s: operationId %s is used twice", method, path, op.OperationID)
			}
			ids[op.OperationID] = true
		}
	}
	if ops != len(h.routes) {
		t.Errorf("%d operations for %d routes", ops, len(h.routes))
	}
	for _, m := range regexp.MustCompile(`"#/components/schemas/([^"]+)"`).FindAllStringSubmatch(string(got), -1) {
		if s, ok := doc.Components.Schemas[m[1]]; !ok || string(s) == "null" {
			t.Errorf("$ref %s has no schema", m[1])
		}
	}
	for name := range doc.Components.Schemas {
		if strings.ContainsAny(name, "[]./") {
			t.Errorf("schema name %q is not a clean identifier", name)
		}
	}
}

// A route with no description, or a description of no route, is refused.
func TestOpenAPIRefusesAnUndescribedRoute(t *testing.T) {
	saved := routeDocs["GET /api/admin/v1/devices"]
	delete(routeDocs, "GET /api/admin/v1/devices")
	defer func() { routeDocs["GET /api/admin/v1/devices"] = saved }()
	if _, err := (&Handler{}).OpenAPI(); err == nil || !strings.Contains(err.Error(), "GET /api/admin/v1/devices") {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenAPIIsServed(t *testing.T) {
	h := &Handler{}
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/admin/v1/openapi.json", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || doc["openapi"] != "3.1.0" {
		t.Fatalf("doc = %v, %v", doc["openapi"], err)
	}
}
