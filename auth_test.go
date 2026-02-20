// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package httpdata

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/plugins"
	inmemtst "github.com/open-policy-agent/opa/v1/storage/inmem/test"
)

// newManagerWithAuthPlugin creates a plugins.Manager whose service config
// references a custom auth plugin by name, and registers that plugin.
func newManagerWithAuthPlugin(t *testing.T, serverURL, pluginName string, authPlugin plugins.Plugin) *plugins.Manager {
	t.Helper()
	cfg := fmt.Appendf(nil, `{
		"services": [{
			"name": "testsvc",
			"url": %q,
			"credentials": {
				"plugin": %q
			}
		}]
	}`, serverURL, pluginName)

	manager, err := plugins.New(cfg, "test-id", inmemtst.New())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	manager.Register(pluginName, authPlugin)
	return manager
}

// ─────────────────────────────────────────────────────────────
// HeadersAuthPlugin tests
// ─────────────────────────────────────────────────────────────

// TestHeadersAuthPlugin_HeadersPresent verifies that every request made via a
// service configured with HeadersAuthPlugin carries the configured headers.
func TestHeadersAuthPlugin_HeadersPresent(t *testing.T) {
	t.Parallel()

	var gotKey, gotTenant string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Api-Key")
		gotTenant = r.Header.Get("X-Tenant")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	authPlugin := &HeadersAuthPlugin{
		Headers: map[string]string{
			"X-Api-Key": "supersecret",
			"X-Tenant":  "acme",
		},
	}

	manager := newManagerWithAuthPlugin(t, ts.URL, "headers_auth", authPlugin)

	resp, err := manager.Client("testsvc").Do(context.Background(), "GET", "/")
	if err != nil {
		t.Fatalf("Do() returned error: %v", err)
	}
	resp.Body.Close()

	if gotKey != "supersecret" {
		t.Errorf("expected X-Api-Key=supersecret, got %q", gotKey)
	}
	if gotTenant != "acme" {
		t.Errorf("expected X-Tenant=acme, got %q", gotTenant)
	}
}

// TestHeadersAuthPlugin_EmptyHeaders verifies that an empty Headers map causes
// no extra headers to be added and the request still succeeds.
func TestHeadersAuthPlugin_EmptyHeaders(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	authPlugin := &HeadersAuthPlugin{Headers: map[string]string{}}
	manager := newManagerWithAuthPlugin(t, ts.URL, "headers_auth_empty", authPlugin)

	resp, err := manager.Client("testsvc").Do(context.Background(), "GET", "/")
	if err != nil {
		t.Fatalf("Do() returned unexpected error: %v", err)
	}
	resp.Body.Close()
}

// TestHeadersAuthPlugin_PluginInterface verifies that HeadersAuthPlugin
// satisfies the plugins.Plugin interface (Start/Stop/Reconfigure are no-ops).
func TestHeadersAuthPlugin_PluginInterface(t *testing.T) {
	t.Parallel()

	p := &HeadersAuthPlugin{Headers: map[string]string{"X-Test": "1"}}
	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}
	p.Reconfigure(ctx, nil)
	p.Stop(ctx)
}

// ─────────────────────────────────────────────────────────────
// HMACAuthPlugin tests
// ─────────────────────────────────────────────────────────────

// TestHMACAuthPlugin_SignatureValid verifies that the HMAC-SHA256 signature
// produced by the plugin is mathematically correct and verifiable server-side.
func TestHMACAuthPlugin_SignatureValid(t *testing.T) {
	t.Parallel()

	const secret = "my-shared-secret"
	fixedTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	var gotSig, gotTs string
	var gotMethod, gotPath string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Signature")
		gotTs = r.Header.Get("X-Timestamp")
		gotMethod = r.Method
		gotPath = r.URL.RequestURI()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	authPlugin := &HMACAuthPlugin{
		Secret: secret,
		now:    func() time.Time { return fixedTime },
	}

	manager := newManagerWithAuthPlugin(t, ts.URL, "hmac_auth", authPlugin)

	resp, err := manager.Client("testsvc").Do(context.Background(), "GET", "/api/data")
	if err != nil {
		t.Fatalf("Do() returned error: %v", err)
	}
	resp.Body.Close()

	if gotSig == "" {
		t.Fatal("expected X-Signature header to be set, got empty string")
	}
	if gotTs == "" {
		t.Fatal("expected X-Timestamp header to be set, got empty string")
	}

	// Reconstruct the expected signature server-side and verify it matches.
	emptyBodyHash := sha256.Sum256([]byte{})
	expectedPayload := fmt.Sprintf("%s\n%s\n%s\n%s",
		gotMethod,
		gotPath,
		fixedTime.UTC().Format(time.RFC3339),
		hex.EncodeToString(emptyBodyHash[:]),
	)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(expectedPayload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(gotSig), []byte(expectedSig)) {
		t.Errorf("signature mismatch:\n  got:  %s\n  want: %s", gotSig, expectedSig)
	}
}

// TestHMACAuthPlugin_CustomHeaderNames verifies that custom header names are
// honoured.
func TestHMACAuthPlugin_CustomHeaderNames(t *testing.T) {
	t.Parallel()

	var gotSig, gotTs string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Hub-Signature-256")
		gotTs = r.Header.Get("X-Request-Time")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	authPlugin := &HMACAuthPlugin{
		Secret:          "secret",
		SignatureHeader: "X-Hub-Signature-256",
		TimestampHeader: "X-Request-Time",
	}

	manager := newManagerWithAuthPlugin(t, ts.URL, "hmac_custom", authPlugin)

	resp, err := manager.Client("testsvc").Do(context.Background(), "GET", "/")
	if err != nil {
		t.Fatalf("Do() returned error: %v", err)
	}
	resp.Body.Close()

	if gotSig == "" {
		t.Error("expected X-Hub-Signature-256 to be set")
	}
	if gotTs == "" {
		t.Error("expected X-Request-Time to be set")
	}
}

// TestHMACAuthPlugin_EmptySecretError verifies that Prepare returns an error
// when the Secret field is empty.
func TestHMACAuthPlugin_EmptySecretError(t *testing.T) {
	t.Parallel()

	p := &HMACAuthPlugin{Secret: ""}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Prepare(req); err == nil {
		t.Error("expected error for empty Secret, got nil")
	}
}

// TestHMACAuthPlugin_DifferentSecretsProduceDifferentSigs verifies that two
// plugins with different secrets produce different signatures for the same
// request.
func TestHMACAuthPlugin_DifferentSecretsProduceDifferentSigs(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	mkReq := func() *http.Request {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/path", nil)
		return req
	}

	p1 := &HMACAuthPlugin{Secret: "secret-A", now: func() time.Time { return fixedTime }}
	p2 := &HMACAuthPlugin{Secret: "secret-B", now: func() time.Time { return fixedTime }}

	r1, r2 := mkReq(), mkReq()
	if err := p1.Prepare(r1); err != nil {
		t.Fatal(err)
	}
	if err := p2.Prepare(r2); err != nil {
		t.Fatal(err)
	}

	sig1 := r1.Header.Get(defaultHMACHeader)
	sig2 := r2.Header.Get(defaultHMACHeader)

	if sig1 == sig2 {
		t.Errorf("expected different signatures for different secrets, both got %q", sig1)
	}
}

// TestHMACAuthPlugin_PluginInterface verifies that HMACAuthPlugin satisfies
// the plugins.Plugin interface.
func TestHMACAuthPlugin_PluginInterface(t *testing.T) {
	t.Parallel()

	p := &HMACAuthPlugin{Secret: "s"}
	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}
	p.Reconfigure(ctx, nil)
	p.Stop(ctx)
}
