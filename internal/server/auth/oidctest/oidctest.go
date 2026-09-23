// Package oidctest is an in-process OpenID Connect provider for tests:
// discovery, signing keys and a token endpoint that checks PKCE, on an
// httptest TLS server. No test ever talks to a real identity provider.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Provider is a fake identity provider.
type Provider struct {
	Server   *httptest.Server
	ClientID string

	key   *rsa.PrivateKey
	mu    sync.Mutex
	codes map[string]grant
}

// Person is who signs in at the provider.
type Person struct {
	Subject string
	Email   string
	Groups  []string
}

// grant is an authorization code the provider has handed out, waiting to be
// exchanged.
type grant struct {
	challenge string
	claims    map[string]any
	// key, when set, signs the token instead of the provider's own key.
	key *rsa.PrivateKey
}

// New starts a provider that issues tokens for clientID.
func New(t *testing.T, clientID string) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{ClientID: clientID, key: key, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /keys", p.keys)
	mux.HandleFunc("POST /token", p.token)
	p.Server = httptest.NewTLSServer(mux)
	t.Cleanup(p.Server.Close)
	return p
}

// Issuer is the provider's issuer URL.
func (p *Provider) Issuer() string { return p.Server.URL }

// Client trusts the provider's certificate.
func (p *Provider) Client() *http.Client { return p.Server.Client() }

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.Issuer(),
		"authorization_endpoint":                p.Issuer() + "/authorize",
		"token_endpoint":                        p.Issuer() + "/token",
		"jwks_uri":                              p.Issuer() + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *Provider) keys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &p.key.PublicKey, KeyID: "test-key", Algorithm: string(jose.RS256), Use: "sig",
	}}})
}

// Authorize plays the part of the browser at the provider: it reads the
// authorization URL a sign-in was sent to, signs person in, and returns the
// callback's state and code. extra claims override the defaults, so a test
// can send a token with the wrong audience or an expiry in the past.
func (p *Provider) Authorize(t *testing.T, authURL string, person Person, extra map[string]any) (state, code string) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("the sign-in did not use PKCE with S256: %s", authURL)
	}
	now := time.Now()
	claims := map[string]any{
		"iss": p.Issuer(), "aud": p.ClientID, "sub": person.Subject,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": q.Get("nonce"),
	}
	if person.Email != "" {
		claims["email"] = person.Email
	}
	if person.Groups != nil {
		claims["groups"] = person.Groups
	}
	for k, v := range extra {
		claims[k] = v
	}
	code = randomString(t)
	p.mu.Lock()
	p.codes[code] = grant{challenge: q.Get("code_challenge"), claims: claims}
	p.mu.Unlock()
	return q.Get("state"), code
}

// token exchanges a code for an ID token, and refuses a verifier that does
// not match the challenge the code was issued against - which is the whole
// point of PKCE, so the fake insists on it as a real provider would.
func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	g, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	if !ok {
		writeError(w, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		writeError(w, "invalid_grant")
		return
	}
	key := p.key
	if g.key != nil {
		key = g.key
	}
	idToken, err := SignWith(key, g.claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken})
}

// SignWith signs claims with some other key, for a token the provider never
// issued.
func SignWith(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"))
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// ForgeCode registers a code whose token is signed by a key the provider does
// not publish, so the relying party must refuse it.
func (p *Provider) ForgeCode(t *testing.T, authURL string, person Person) (state, code string) {
	t.Helper()
	state, code = p.Authorize(t, authURL, person, nil)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	g := p.codes[code]
	g.key = other
	p.codes[code] = g
	return state, code
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func randomString(t *testing.T) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
