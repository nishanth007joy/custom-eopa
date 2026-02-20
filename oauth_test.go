// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package httpdata

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/plugins"
	inmemtst "github.com/open-policy-agent/opa/v1/storage/inmem/test"
)

// fakeTokenServer is a configurable OAuth2 token endpoint for tests.
type fakeTokenServer struct {
	AccessToken string
	ExpiresIn   int64
	StatusCode  int
	Error       string
	// counts how many token requests have been served
	RequestCount atomic.Int32
}

func (f *fakeTokenServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.RequestCount.Add(1)

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}

		code := f.StatusCode
		if code == 0 {
			code = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)

		if f.Error != "" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             f.Error,
				"error_description": "test error",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": f.AccessToken,
			"token_type":   "Bearer",
			"expires_in":   f.ExpiresIn,
		})
	})
}

// TestOAuthPlugin_TokenAttachedAsBearer verifies that a successful token fetch
// results in the Authorization: Bearer <token> header being present on the
// downstream request.
func TestOAuthPlugin_TokenAttachedAsBearer(t *testing.T) {
	t.Parallel()

	tokenSrv := &fakeTokenServer{AccessToken: "test-access-token", ExpiresIn: 3600}
	ts := httptest.NewServer(tokenSrv.handler())
	defer ts.Close()

	var gotAuth string
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer apiSrv.Close()

	plugin := &OAuthClientCredentialsPlugin{
		TokenURL:     ts.URL + "/token",
		ClientID:     "my-client",
		ClientSecret: "my-secret",
	}

	manager := newManagerWithAuthPlugin(t, apiSrv.URL, "oauth_plugin", plugin)

	resp, err := manager.Client("testsvc").Do(context.Background(), "GET", "/api/resource")
	if err != nil {
		t.Fatalf("Do() failed: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer test-access-token" {
		t.Errorf("expected Authorization: Bearer test-access-token, got %q", gotAuth)
	}
}

// TestOAuthPlugin_TokenCached verifies that multiple requests use the cached
// token and do not hit the token endpoint more than once.
func TestOAuthPlugin_TokenCached(t *testing.T) {
	t.Parallel()

	tokenSrv := &fakeTokenServer{AccessToken: "cached-token", ExpiresIn: 3600}
	ts := httptest.NewServer(tokenSrv.handler())
	defer ts.Close()

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer apiSrv.Close()

	plugin := &OAuthClientCredentialsPlugin{
		TokenURL:     ts.URL + "/token",
		ClientID:     "client",
		ClientSecret: "secret",
	}

	manager := newManagerWithAuthPlugin(t, apiSrv.URL, "oauth_cached", plugin)

	for range 5 {
		resp, err := manager.Client("testsvc").Do(context.Background(), "GET", "/")
		if err != nil {
			t.Fatalf("Do() failed: %v", err)
		}
		resp.Body.Close()
	}

	if n := tokenSrv.RequestCount.Load(); n != 1 {
		t.Errorf("expected 1 token request, got %d", n)
	}
}

// TestOAuthPlugin_TokenRefreshedWhenExpired verifies that a token is refreshed
// once the cached copy falls within ExpiryMargin of its expiry time.
func TestOAuthPlugin_TokenRefreshedWhenExpired(t *testing.T) {
	t.Parallel()

	tokenSrv := &fakeTokenServer{AccessToken: "fresh-token", ExpiresIn: 60}
	ts := httptest.NewServer(tokenSrv.handler())
	defer ts.Close()

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer apiSrv.Close()

	// Advance time so the token is within ExpiryMargin.
	virtualNow := time.Now()
	plugin := &OAuthClientCredentialsPlugin{
		TokenURL:     ts.URL + "/token",
		ClientID:     "client",
		ClientSecret: "secret",
		ExpiryMargin: 30 * time.Second,
		now:          func() time.Time { return virtualNow },
	}

	// First call — fetches token (expires in 60s from virtualNow).
	tok, err := plugin.accessToken(context.Background())
	if err != nil {
		t.Fatalf("first accessToken() failed: %v", err)
	}
	if tok != "fresh-token" {
		t.Errorf("unexpected token %q", tok)
	}
	if tokenSrv.RequestCount.Load() != 1 {
		t.Errorf("expected 1 token request after first call")
	}

	// Advance time to within 25s of expiry — now inside the ExpiryMargin of 30s.
	virtualNow = virtualNow.Add(36 * time.Second)

	tok, err = plugin.accessToken(context.Background())
	if err != nil {
		t.Fatalf("second accessToken() failed: %v", err)
	}
	if tok != "fresh-token" {
		t.Errorf("unexpected token %q", tok)
	}
	if n := tokenSrv.RequestCount.Load(); n != 2 {
		t.Errorf("expected 2 token requests after refresh, got %d", n)
	}
}

// TestOAuthPlugin_TokenEndpointError verifies that a non-200 from the token
// endpoint is propagated as an error.
func TestOAuthPlugin_TokenEndpointError(t *testing.T) {
	t.Parallel()

	tokenSrv := &fakeTokenServer{StatusCode: http.StatusUnauthorized, Error: "invalid_client"}
	ts := httptest.NewServer(tokenSrv.handler())
	defer ts.Close()

	plugin := &OAuthClientCredentialsPlugin{
		TokenURL:     ts.URL + "/token",
		ClientID:     "bad-client",
		ClientSecret: "bad-secret",
	}

	_, err := plugin.accessToken(context.Background())
	if err == nil {
		t.Fatal("expected error for 401 token response, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected error to mention HTTP 401, got: %v", err)
	}
}

// TestOAuthPlugin_OAuthErrorField verifies that an OAuth2 error field in a
// 200 response body is surfaced as an error.
func TestOAuthPlugin_OAuthErrorField(t *testing.T) {
	t.Parallel()

	tokenSrv := &fakeTokenServer{
		StatusCode: http.StatusOK,
		Error:      "access_denied",
	}
	ts := httptest.NewServer(tokenSrv.handler())
	defer ts.Close()

	plugin := &OAuthClientCredentialsPlugin{
		TokenURL:     ts.URL + "/token",
		ClientID:     "client",
		ClientSecret: "secret",
	}

	_, err := plugin.accessToken(context.Background())
	if err == nil {
		t.Fatal("expected error for OAuth error response, got nil")
	}
	if !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("expected error to mention access_denied, got: %v", err)
	}
}

// TestOAuthPlugin_MissingFields verifies that missing required config fields
// return meaningful errors.
func TestOAuthPlugin_MissingFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		plugin *OAuthClientCredentialsPlugin
		want   string
	}{
		{
			name:   "missing TokenURL",
			plugin: &OAuthClientCredentialsPlugin{ClientID: "a", ClientSecret: "b"},
			want:   "TokenURL is required",
		},
		{
			name:   "missing ClientID",
			plugin: &OAuthClientCredentialsPlugin{TokenURL: "http://x", ClientSecret: "b"},
			want:   "ClientID is required",
		},
		{
			name:   "missing ClientSecret",
			plugin: &OAuthClientCredentialsPlugin{TokenURL: "http://x", ClientID: "a"},
			want:   "ClientSecret is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tc.plugin.accessToken(context.Background())
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected error to contain %q, got: %v", tc.want, err)
			}
		})
	}
}

// TestOAuthPlugin_ScopesAndExtraParams verifies that scopes and extra params
// are sent to the token endpoint.
func TestOAuthPlugin_ScopesAndExtraParams(t *testing.T) {
	t.Parallel()

	var gotForm url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   int64(3600),
		})
	}))
	defer ts.Close()

	plugin := &OAuthClientCredentialsPlugin{
		TokenURL:     ts.URL + "/token",
		ClientID:     "client",
		ClientSecret: "secret",
		Scopes:       []string{"read:data", "write:data"},
		ExtraParams:  map[string]string{"audience": "https://api.example.com"},
	}

	_, err := plugin.accessToken(context.Background())
	if err != nil {
		t.Fatalf("accessToken() failed: %v", err)
	}

	if got := gotForm.Get("scope"); got != "read:data write:data" {
		t.Errorf("expected scope %q, got %q", "read:data write:data", got)
	}
	if got := gotForm.Get("audience"); got != "https://api.example.com" {
		t.Errorf("expected audience %q, got %q", "https://api.example.com", got)
	}
}

// TestOAuthPlugin_StopClearsCache verifies that Stop() clears the token cache
// so the next Prepare call fetches a fresh token.
func TestOAuthPlugin_StopClearsCache(t *testing.T) {
	t.Parallel()

	tokenSrv := &fakeTokenServer{AccessToken: "tok", ExpiresIn: 3600}
	ts := httptest.NewServer(tokenSrv.handler())
	defer ts.Close()

	plugin := &OAuthClientCredentialsPlugin{
		TokenURL:     ts.URL + "/token",
		ClientID:     "client",
		ClientSecret: "secret",
	}

	// Warm the cache.
	if _, err := plugin.accessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := tokenSrv.RequestCount.Load(); n != 1 {
		t.Fatalf("expected 1 request, got %d", n)
	}

	// Stop should clear the cache.
	plugin.Stop(context.Background())

	// Next call must fetch a new token.
	if _, err := plugin.accessToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := tokenSrv.RequestCount.Load(); n != 2 {
		t.Errorf("expected 2 token requests after Stop(), got %d", n)
	}
}

// TestOAuthPlugin_PluginInterface verifies all Plugin interface methods.
func TestOAuthPlugin_PluginInterface(t *testing.T) {
	t.Parallel()

	p := &OAuthClientCredentialsPlugin{
		TokenURL:     "http://unused",
		ClientID:     "c",
		ClientSecret: "s",
	}
	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}
	p.Reconfigure(ctx, nil)
	p.Stop(ctx)
}

// TestOAuthPlugin_DefaultExpiresIn verifies that when the token server omits
// expires_in, the plugin defaults to 1 hour.
func TestOAuthPlugin_DefaultExpiresIn(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Intentionally omit expires_in.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
		})
	}))
	defer ts.Close()

	fixedNow := time.Now()
	plugin := &OAuthClientCredentialsPlugin{
		TokenURL:     ts.URL + "/token",
		ClientID:     "c",
		ClientSecret: "s",
		now:          func() time.Time { return fixedNow },
	}

	if _, err := plugin.accessToken(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Without expires_in, expiry should be 1 hour from fixedNow.
	expected := fixedNow.Add(time.Hour)
	if !plugin.token.expiresAt.Equal(expected) {
		t.Errorf("expected expiresAt %v, got %v", expected, plugin.token.expiresAt)
	}
}

// TestOAuthPlugin_EndToEnd exercises the full path: plugin registered with a
// Manager, service client used via httpdata plugin to fetch data, with OAuth
// token auth flowing through.
func TestOAuthPlugin_EndToEnd(t *testing.T) {
	t.Parallel()

	const token = "end-to-end-token"

	tokenSrv := &fakeTokenServer{AccessToken: token, ExpiresIn: 3600}
	tokenTS := httptest.NewServer(tokenSrv.handler())
	defer tokenTS.Close()

	// API server that requires a valid Bearer token.
	apiTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"result": "ok"})
	}))
	defer apiTS.Close()

	oauthPlugin := &OAuthClientCredentialsPlugin{
		TokenURL:     tokenTS.URL + "/token",
		ClientID:     "client",
		ClientSecret: "secret",
	}

	// Build manager with both: the service using the oauth auth plugin, and the
	// httpdata plugin pointing at the API server.
	cfg := fmt.Appendf(nil, `{
		"services": [{
			"name": "testsvc",
			"url": %q,
			"credentials": {"plugin": "my_oauth"}
		}]
	}`, apiTS.URL)
	manager, err := plugins.New(cfg, "test-id", inmemtst.New())
	if err != nil {
		t.Fatalf("plugins.New: %v", err)
	}
	manager.Register("my_oauth", oauthPlugin)

	dataCfg := Config{
		Service:         "testsvc",
		Endpoint:        "/data",
		Method:          "GET",
		Path:            "/oauth/result",
		IntervalSeconds: 3600,
	}
	_ = dataCfg.validateAndInjectDefaults(manager.Services())

	p := &Plugin{
		manager:  manager,
		config:   dataCfg,
		stop:     make(chan chan struct{}),
		reconfig: make(chan Config),
		logger:   manager.Logger().WithFields(map[string]any{"plugin": PluginName}),
	}
	manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	defer p.Stop(ctx)

	// After Start, the initial fetch should have succeeded.
	val := readStorePath(t, ctx, manager, "/oauth/result")
	gotMap, ok := val.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T: %v", val, val)
	}
	if gotMap["result"] != "ok" {
		t.Errorf("expected result=ok, got %v", gotMap["result"])
	}

	status := pluginStatus(manager)
	if status == nil || status.State != plugins.StateOK {
		t.Errorf("expected StateOK, got %v", status)
	}
}

// ─────────────────────────────────────────────────────────────
// OAuthAuthFactory tests
// ─────────────────────────────────────────────────────────────

// TestOAuthAuthFactory_ValidateSucceeds verifies that a complete config is
// parsed correctly and all fields are populated.
func TestOAuthAuthFactory_ValidateSucceeds(t *testing.T) {
	t.Parallel()

	factory := &OAuthAuthFactory{}
	raw := []byte(`{
		"token_url":             "https://auth.example.com/token",
		"client_id":             "my-client",
		"client_secret":         "my-secret",
		"scopes":                ["read:data", "write:data"],
		"extra_params":          {"audience": "https://api.example.com"},
		"expiry_margin_seconds": 60
	}`)

	val, err := factory.Validate(nil, raw)
	if err != nil {
		t.Fatalf("Validate() returned unexpected error: %v", err)
	}

	cfg, ok := val.(OAuthAuthConfig)
	if !ok {
		t.Fatalf("expected OAuthAuthConfig, got %T", val)
	}

	if cfg.TokenURL != "https://auth.example.com/token" {
		t.Errorf("TokenURL: got %q, want %q", cfg.TokenURL, "https://auth.example.com/token")
	}
	if cfg.ClientID != "my-client" {
		t.Errorf("ClientID: got %q, want %q", cfg.ClientID, "my-client")
	}
	if cfg.ClientSecret != "my-secret" {
		t.Errorf("ClientSecret: got %q, want %q", cfg.ClientSecret, "my-secret")
	}
	if len(cfg.Scopes) != 2 || cfg.Scopes[0] != "read:data" || cfg.Scopes[1] != "write:data" {
		t.Errorf("Scopes: got %v, want [read:data write:data]", cfg.Scopes)
	}
	if cfg.ExtraParams["audience"] != "https://api.example.com" {
		t.Errorf("ExtraParams[audience]: got %q, want %q", cfg.ExtraParams["audience"], "https://api.example.com")
	}
	if cfg.ExpiryMarginSeconds != 60 {
		t.Errorf("ExpiryMarginSeconds: got %d, want 60", cfg.ExpiryMarginSeconds)
	}
}

// TestOAuthAuthFactory_ValidateMissingFields verifies that each missing
// required field returns a descriptive error.
func TestOAuthAuthFactory_ValidateMissingFields(t *testing.T) {
	t.Parallel()

	factory := &OAuthAuthFactory{}

	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "missing token_url",
			raw:  []byte(`{"client_id":"c","client_secret":"s"}`),
			want: "token_url",
		},
		{
			name: "missing client_id",
			raw:  []byte(`{"token_url":"https://t","client_secret":"s"}`),
			want: "client_id",
		},
		{
			name: "missing client_secret",
			raw:  []byte(`{"token_url":"https://t","client_id":"c"}`),
			want: "client_secret",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := factory.Validate(nil, tc.raw)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected error to mention %q, got: %v", tc.want, err)
			}
		})
	}
}

// TestOAuthAuthFactory_DefaultExpiryMargin verifies that when
// expiry_margin_seconds is omitted, New() defaults to 30 seconds.
func TestOAuthAuthFactory_DefaultExpiryMargin(t *testing.T) {
	t.Parallel()

	factory := &OAuthAuthFactory{}
	raw := []byte(`{"token_url":"https://t","client_id":"c","client_secret":"s"}`)

	val, err := factory.Validate(nil, raw)
	if err != nil {
		t.Fatalf("Validate() returned unexpected error: %v", err)
	}

	p := factory.New(nil, val).(*OAuthClientCredentialsPlugin)
	if p.ExpiryMargin != 30*time.Second {
		t.Errorf("expected ExpiryMargin=30s, got %v", p.ExpiryMargin)
	}
}

// TestOAuthAuthFactory_New verifies that the factory creates a plugin with the
// correct fields, and that accessToken() against a fake server returns the token.
func TestOAuthAuthFactory_New(t *testing.T) {
	t.Parallel()

	tokenSrv := &fakeTokenServer{AccessToken: "factory-token", ExpiresIn: 3600}
	ts := httptest.NewServer(tokenSrv.handler())
	defer ts.Close()

	factory := &OAuthAuthFactory{}
	cfgJSON := fmt.Appendf(nil, `{
		"token_url":             %q,
		"client_id":             "factory-client",
		"client_secret":         "factory-secret",
		"scopes":                ["read:data"],
		"extra_params":          {"audience": "https://api.example.com"},
		"expiry_margin_seconds": 45
	}`, ts.URL+"/token")

	val, err := factory.Validate(nil, cfgJSON)
	if err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}

	plugin := factory.New(nil, val).(*OAuthClientCredentialsPlugin)

	// Verify fields are mapped correctly.
	if plugin.TokenURL != ts.URL+"/token" {
		t.Errorf("TokenURL: got %q, want %q", plugin.TokenURL, ts.URL+"/token")
	}
	if plugin.ClientID != "factory-client" {
		t.Errorf("ClientID: got %q", plugin.ClientID)
	}
	if plugin.ClientSecret != "factory-secret" {
		t.Errorf("ClientSecret: got %q", plugin.ClientSecret)
	}
	if len(plugin.Scopes) != 1 || plugin.Scopes[0] != "read:data" {
		t.Errorf("Scopes: got %v", plugin.Scopes)
	}
	if plugin.ExtraParams["audience"] != "https://api.example.com" {
		t.Errorf("ExtraParams: got %v", plugin.ExtraParams)
	}
	if plugin.ExpiryMargin != 45*time.Second {
		t.Errorf("ExpiryMargin: got %v, want 45s", plugin.ExpiryMargin)
	}

	// Verify the plugin can actually fetch a token.
	tok, err := plugin.accessToken(context.Background())
	if err != nil {
		t.Fatalf("accessToken() failed: %v", err)
	}
	if tok != "factory-token" {
		t.Errorf("token: got %q, want %q", tok, "factory-token")
	}
}

// TestOAuthAuthFactory_ManagerRoundTrip is a full simulation:
// Validate → New → manager.Register → manager.AuthPlugin non-nil;
// service client hits API server with Authorization: Bearer <token>.
func TestOAuthAuthFactory_ManagerRoundTrip(t *testing.T) {
	t.Parallel()

	const wantToken = "roundtrip-token"

	tokenSrv := &fakeTokenServer{AccessToken: wantToken, ExpiresIn: 3600}
	tokenTS := httptest.NewServer(tokenSrv.handler())
	defer tokenTS.Close()

	var gotAuth string
	apiTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer apiTS.Close()

	// Build manager with a service that references the factory plugin.
	managerCfg := fmt.Appendf(nil, `{
		"services": [{
			"name": "testsvc",
			"url": %q,
			"credentials": {"plugin": "my_oauth"}
		}]
	}`, apiTS.URL)
	manager, err := plugins.New(managerCfg, "test-id", inmemtst.New())
	if err != nil {
		t.Fatalf("plugins.New: %v", err)
	}

	// Run the factory Validate → New cycle.
	factory := &OAuthAuthFactory{}
	pluginCfg := fmt.Appendf(nil, `{
		"token_url":   %q,
		"client_id":   "rt-client",
		"client_secret": "rt-secret"
	}`, tokenTS.URL+"/token")

	val, err := factory.Validate(manager, pluginCfg)
	if err != nil {
		t.Fatalf("factory.Validate: %v", err)
	}
	plugin := factory.New(manager, val)

	manager.Register("my_oauth", plugin)

	// AuthPlugin must return the registered plugin.
	if ap := manager.AuthPlugin("my_oauth"); ap == nil {
		t.Fatal("manager.AuthPlugin(\"my_oauth\") returned nil")
	}

	// Make a request through the service; it should carry the Bearer token.
	resp, err := manager.Client("testsvc").Do(context.Background(), "GET", "/resource")
	if err != nil {
		t.Fatalf("Do() failed: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer "+wantToken {
		t.Errorf("Authorization header: got %q, want %q", gotAuth, "Bearer "+wantToken)
	}
}
