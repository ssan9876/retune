package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The OpenAPI document is generated from the routes as registered and the
// Go types the handlers really encode and decode, so it cannot drift from
// the API: TestOpenAPIDocument fails when a route has no entry in routeDocs,
// when an entry names a route that does not exist, or when the committed
// docs/openapi.json is not what this code produces.

// param is a path or query parameter.
type param struct {
	Name, In, Description string
	// Type is "string", "integer" or "boolean"; string if empty.
	Type string
}

// routeDoc describes one route.
type routeDoc struct {
	Summary     string
	Description string
	Tag         string
	// Request is a value of the JSON request body's type, or nil for none.
	Request any
	// RequestContent is the media type of a request body that isn't JSON.
	RequestContent string
	Query          []param
	// Status is the success status; 200 if zero.
	Status int
	// Response is a value of the JSON response body's type, or nil for none.
	Response any
	// ResponseContent is the media type of a response that isn't JSON.
	ResponseContent string
	// Held marks a request two-person approval may hold, answering 202.
	Held bool
}

var pathParam = regexp.MustCompile(`\{([A-Za-z]+)\}`)

// accessDescriptions say what each access class means for a caller.
var accessDescriptions = map[string]string{
	"public":          "No sign-in.",
	"scoped":          "Any signed-in admin or API token; a scoped admin sees only their devices.",
	"scoped+write":    "The admin role; a scoped admin within their devices.",
	"scoped+operate":  "The admin or helpdesk role; a scoped admin within their devices.",
	"fleet":           "Any signed-in admin or API token, not limited to some devices.",
	"fleet+write":     "The admin role, not limited to some devices.",
	"session":         "A person signed in to the console; not an API token.",
	"session+write":   "The admin role, signed in to the console.",
	"session+operate": "The admin or helpdesk role, signed in to the console.",
	"admin":           "Signed in to the console, not limited to some devices.",
	"admin+write":     "The admin role, signed in to the console, not limited to some devices.",
}

// routeClass names who may call a route.
func routeClass(g guarded) string {
	if g.open {
		return "public"
	}
	c := "scoped"
	switch {
	case g.access.session && g.access.fleet:
		c = "admin"
	case g.access.session:
		c = "session"
	case g.access.fleet:
		c = "fleet"
	}
	if g.access.admin {
		c += "+write"
	}
	if g.access.operate {
		c += "+operate"
	}
	return c
}

// OpenAPI returns the admin API's OpenAPI 3.1 document.
func (h *Handler) OpenAPI() ([]byte, error) {
	if h.routes == nil {
		h.Routes()
	}
	g := &schemaGen{schemas: map[string]any{}, names: map[reflect.Type]string{}}
	paths := map[string]map[string]any{}
	var missing []string
	// In a fixed order: two types with the same name are told apart by
	// package, and which one keeps the plain name must not change from one
	// run to the next.
	patterns := make([]string, 0, len(h.routes))
	for pattern := range h.routes {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	for _, pattern := range patterns {
		route := h.routes[pattern]
		doc, ok := routeDocs[pattern]
		if !ok {
			missing = append(missing, pattern)
			continue
		}
		method, full, _ := strings.Cut(pattern, " ")
		path := strings.TrimPrefix(full, apiBase)
		op, err := g.operation(method, path, doc, routeClass(route))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pattern, err)
		}
		if paths[path] == nil {
			paths[path] = map[string]any{}
		}
		paths[path][strings.ToLower(method)] = op
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("routes with no entry in routeDocs: %s", strings.Join(missing, ", "))
	}
	for pattern := range routeDocs {
		if _, ok := h.routes[pattern]; !ok {
			return nil, fmt.Errorf("routeDocs describes %s, which is not a route", pattern)
		}
	}
	g.schemas["Error"] = map[string]any{
		"type": "object",
		"properties": map[string]any{
			"code":    map[string]any{"type": "string"},
			"message": map[string]any{"type": "string"},
		},
	}
	doc := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "Retune admin API",
			"version": "1",
			"description": "The API the Retune console uses. Sign in with a session (the " + SessionCookie +
				" cookie, with the " + CSRFHeader + " header on every change) or send an API token as " +
				"`Authorization: Bearer rtk_…`. Each operation's `x-retune-access` names who may call it. " +
				"Errors are `{\"code\": \"…\", \"message\": \"…\"}`.",
		},
		"servers": []any{map[string]any{"url": apiBase}},
		"paths":   paths,
		"components": map[string]any{
			"schemas": g.schemas,
			"securitySchemes": map[string]any{
				"session": map[string]any{"type": "apiKey", "in": "cookie", "name": SessionCookie,
					"description": "A console session. Changes also need the " + CSRFHeader + " header."},
				"token": map[string]any{"type": "http", "scheme": "bearer",
					"description": "An API token, rtk_…"},
			},
			"responses": map[string]any{
				"Error": map[string]any{
					"description": "An error.",
					"content":     map[string]any{"application/json": map[string]any{"schema": ref("Error")}},
				},
			},
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

const apiBase = "/api/admin/v1"

func ref(name string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + name}
}

func (g *schemaGen) operation(method, path string, doc routeDoc, class string) (map[string]any, error) {
	if doc.Summary == "" || doc.Tag == "" {
		return nil, fmt.Errorf("a summary and a tag are required")
	}
	op := map[string]any{
		"summary":         doc.Summary,
		"tags":            []any{doc.Tag},
		"operationId":     operationID(method, path),
		"x-retune-access": class,
	}
	description := accessDescriptions[class]
	if doc.Description != "" {
		description = doc.Description + "\n\n" + description
	}
	op["description"] = description
	switch {
	case class == "public":
		op["security"] = []any{}
	case strings.HasPrefix(class, "session") || strings.HasPrefix(class, "admin"):
		op["security"] = []any{map[string]any{"session": []any{}}}
	default:
		op["security"] = []any{map[string]any{"session": []any{}}, map[string]any{"token": []any{}}}
	}

	var params []any
	for _, m := range pathParam.FindAllStringSubmatch(path, -1) {
		params = append(params, map[string]any{
			"name": m[1], "in": "path", "required": true,
			"schema": map[string]any{"type": "string"},
		})
	}
	for _, p := range doc.Query {
		typ := p.Type
		if typ == "" {
			typ = "string"
		}
		q := map[string]any{"name": p.Name, "in": "query", "schema": map[string]any{"type": typ}}
		if p.Description != "" {
			q["description"] = p.Description
		}
		params = append(params, q)
	}
	if len(params) > 0 {
		op["parameters"] = params
	}

	switch {
	case doc.RequestContent != "":
		op["requestBody"] = map[string]any{"required": true, "content": map[string]any{
			doc.RequestContent: map[string]any{"schema": map[string]any{"type": "string", "format": "binary"}}}}
	case doc.Request != nil:
		op["requestBody"] = map[string]any{"required": true, "content": map[string]any{
			"application/json": map[string]any{"schema": g.schema(reflect.TypeOf(doc.Request))}}}
	}

	status := doc.Status
	if status == 0 {
		status = http.StatusOK
	}
	ok := map[string]any{"description": http.StatusText(status)}
	switch {
	case doc.ResponseContent != "":
		ok["content"] = map[string]any{doc.ResponseContent: map[string]any{
			"schema": map[string]any{"type": "string", "format": "binary"}}}
	case doc.Response != nil:
		ok["content"] = map[string]any{"application/json": map[string]any{
			"schema": g.schema(reflect.TypeOf(doc.Response))}}
	}
	responses := map[string]any{fmt.Sprint(status): ok, "default": map[string]any{"$ref": "#/components/responses/Error"}}
	if doc.Held {
		responses["202"] = map[string]any{
			"description": "Held for a second administrator's approval.",
			"content": map[string]any{"application/json": map[string]any{
				"schema": g.schema(reflect.TypeOf(approvalEnvelope{}))}},
		}
	}
	op["responses"] = responses
	return op, nil
}

// operationID is a stable name for an operation: its method and path.
func operationID(method, path string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(method))
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '-' || r == '.' }) {
		part = strings.Trim(part, "{}")
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

// schemaGen turns Go types into JSON Schema, naming each struct once in
// components.schemas.
type schemaGen struct {
	schemas map[string]any
	names   map[reflect.Type]string
}

var (
	timeType    = reflect.TypeOf(time.Time{})
	uuidType    = reflect.TypeOf(uuid.UUID{})
	rawJSONType = reflect.TypeOf(json.RawMessage{})
)

func (g *schemaGen) schema(t reflect.Type) map[string]any {
	switch t {
	case timeType:
		return map[string]any{"type": "string", "format": "date-time"}
	case uuidType:
		return map[string]any{"type": "string", "format": "uuid"}
	case rawJSONType:
		return map[string]any{}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return g.schema(t.Elem())
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return map[string]any{"type": "string", "contentEncoding": "base64"}
		}
		return map[string]any{"type": "array", "items": g.schema(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": g.schema(t.Elem())}
	case reflect.Interface:
		return map[string]any{}
	case reflect.Struct:
		if t.Name() == "" {
			return g.object(t)
		}
		name := g.name(t)
		if _, done := g.schemas[name]; !done {
			g.schemas[name] = nil // placeholder, for types that refer to themselves
			g.schemas[name] = g.object(t)
		}
		return ref(name)
	}
	return map[string]any{}
}

func (g *schemaGen) object(t reflect.Type) map[string]any {
	props := map[string]any{}
	g.fields(t, props)
	return map[string]any{"type": "object", "properties": props}
}

func (g *schemaGen) fields(t reflect.Type, props map[string]any) {
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			g.fields(ft, props)
			continue
		}
		if name == "-" || (!f.IsExported() && tag == "") {
			continue
		}
		if name == "" {
			name = f.Name
		}
		props[name] = g.schema(f.Type)
	}
}

var genericArg = regexp.MustCompile(`\[(?:[^\]]*\.)?([A-Za-z0-9_]+)\]`)

// name is the schema name for a Go type: exported-looking, without a JSON
// suffix, and with the package added when two packages share a name.
func (g *schemaGen) name(t reflect.Type) string {
	if n, ok := g.names[t]; ok {
		return n
	}
	raw := t.Name()
	if m := genericArg.FindStringSubmatch(raw); m != nil {
		raw = strings.TrimSuffix(raw[:strings.Index(raw, "[")], "Response") + "Of" + clean(m[1])
	}
	n := clean(raw)
	for other, taken := range g.names {
		if taken == n && other != t {
			pkg := t.PkgPath()
			n = clean(pkg[strings.LastIndex(pkg, "/")+1:]) + n
			break
		}
	}
	g.names[t] = n
	return n
}

func clean(s string) string {
	s = strings.TrimSuffix(s, "JSON")
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// serveOpenAPI answers with the OpenAPI document.
func (h *Handler) serveOpenAPI(w http.ResponseWriter, r *http.Request) {
	body, err := h.OpenAPI()
	if err != nil {
		h.internal(w, "build the OpenAPI document", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
