// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package httpdata

// OAuthClientCredentialsPlugin implements the OAuth 2.0 Client Credentials
// grant (RFC 6749 §4.4) as a custom HTTPAuthPlugin that can be registered with
// an OPA plugin manager and referenced from any service config by name.
//
// Unlike OPA's built-in oauth2 credential type (which is configured statically
// in the OPA config file), this plugin is created programmatically by an
// embedder and registered with manager.Register. This lets the embedder supply
// dynamic values (secrets from a vault, rotating credentials, etc.) that are
// not available at OPA config-parse time.
//
// Usage:
//
//	plugin := &OAuthClientCredentialsPlugin{
//	    TokenURL:     "https://auth.example.com/oauth/token",
//	    ClientID:     "my-client-id",
//	    ClientSecret: os.Getenv("CLIENT_SECRET"),
//	    Scopes:       []string{"read:data"},
//	}
//	manager.Register("my_oauth", plugin)
//
// OPA service config (YAML):
//
//	services:
//	  - name: myapi
//	    url: https://api.example.com
//	    credentials:
//	      plugin: my_oauth
//
// The plugin fetches an access token from TokenURL using the standard
// application/x-www-form-urlencoded client_credentials request and caches it
// until ExpiryMargin before it expires, then fetches a fresh one automatically.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/plugins/rest"
)

// OAuthClientCredentialsPlugin fetches and caches OAuth2 access tokens using
// the Client Credentials grant, then attaches them as Bearer tokens.
type OAuthClientCredentialsPlugin struct {
	// TokenURL is the token endpoint, e.g. "https://auth.example.com/token". (required)
	TokenURL string

	// ClientID is the OAuth2 client identifier. (required)
	ClientID string

	// ClientSecret is the OAuth2 client secret. (required)
	ClientSecret string

	// Scopes is the optional list of OAuth2 scopes to request.
	Scopes []string

	// ExtraParams are additional form parameters sent with the token request
	// (e.g. {"audience": "https://api.example.com"}).
	ExtraParams map[string]string

	// ExpiryMargin is how long before token expiry a refresh is triggered.
	// Defaults to 30 seconds.
	ExpiryMargin time.Duration

	// now is a hook for deterministic time in tests.
	now func() time.Time

	mu    sync.Mutex
	token cachedToken
}

type cachedToken struct {
	value     string
	expiresAt time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"` // seconds
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// NewClient returns a standard HTTP client for the service.
func (p *OAuthClientCredentialsPlugin) NewClient(c rest.Config) (*http.Client, error) {
	tlsCfg, err := rest.DefaultTLSConfig(c)
	if err != nil {
		return nil, fmt.Errorf("OAuthClientCredentialsPlugin: TLS config error: %w", err)
	}
	timeout := int64(10)
	if c.ResponseHeaderTimeoutSeconds != nil {
		timeout = *c.ResponseHeaderTimeoutSeconds
	}
	return rest.DefaultRoundTripperClient(tlsCfg, timeout), nil
}

// Prepare fetches (or returns the cached) access token and attaches it as a
// Bearer Authorization header.
func (p *OAuthClientCredentialsPlugin) Prepare(req *http.Request) error {
	token, err := p.accessToken(req.Context())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// accessToken returns the cached token if still valid, otherwise fetches a new one.
func (p *OAuthClientCredentialsPlugin) accessToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.currentTime()
	margin := p.ExpiryMargin
	if margin <= 0 {
		margin = 30 * time.Second
	}

	if p.token.value != "" && now.Before(p.token.expiresAt.Add(-margin)) {
		return p.token.value, nil
	}

	return p.fetchToken(ctx, now)
}

// fetchToken performs the Client Credentials token request. Must be called
// with p.mu held.
func (p *OAuthClientCredentialsPlugin) fetchToken(ctx context.Context, now time.Time) (string, error) {
	if p.TokenURL == "" {
		return "", fmt.Errorf("OAuthClientCredentialsPlugin: TokenURL is required")
	}
	if p.ClientID == "" {
		return "", fmt.Errorf("OAuthClientCredentialsPlugin: ClientID is required")
	}
	if p.ClientSecret == "" {
		return "", fmt.Errorf("OAuthClientCredentialsPlugin: ClientSecret is required")
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", p.ClientID)
	form.Set("client_secret", p.ClientSecret)
	if len(p.Scopes) > 0 {
		form.Set("scope", strings.Join(p.Scopes, " "))
	}
	for k, v := range p.ExtraParams {
		form.Set(k, v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("OAuthClientCredentialsPlugin: failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("OAuthClientCredentialsPlugin: token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("OAuthClientCredentialsPlugin: failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OAuthClientCredentialsPlugin: token endpoint returned HTTP %d: %s",
			resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("OAuthClientCredentialsPlugin: failed to parse token response: %w", err)
	}
	if tr.Error != "" {
		return "", fmt.Errorf("OAuthClientCredentialsPlugin: token endpoint error %q: %s",
			tr.Error, tr.ErrorDesc)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("OAuthClientCredentialsPlugin: token response missing access_token")
	}

	expiresIn := tr.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600 // default to 1 hour if server omits expires_in
	}

	p.token = cachedToken{
		value:     tr.AccessToken,
		expiresAt: now.Add(time.Duration(expiresIn) * time.Second),
	}
	return p.token.value, nil
}

func (p *OAuthClientCredentialsPlugin) currentTime() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// Start implements plugins.Plugin (no-op — tokens are fetched lazily).
func (*OAuthClientCredentialsPlugin) Start(context.Context) error { return nil }

// Stop implements plugins.Plugin.  It clears the token cache so the next
// Prepare call fetches a fresh token.
func (p *OAuthClientCredentialsPlugin) Stop(context.Context) {
	p.mu.Lock()
	p.token = cachedToken{}
	p.mu.Unlock()
}

// Reconfigure implements plugins.Plugin (no-op — config is set at construction).
func (*OAuthClientCredentialsPlugin) Reconfigure(context.Context, any) {}

// ────────────────────────────────────────────────────────────
// OAuthAuthFactory — YAML-configurable factory for OAuthClientCredentialsPlugin
// ────────────────────────────────────────────────────────────

// OAuthAuthConfig holds the YAML/JSON configuration for OAuthAuthFactory.
// OPA substitutes ${ENV_VAR} in all config bytes before they reach Validate,
// so client_secret: "${CLIENT_SECRET}" works natively.
type OAuthAuthConfig struct {
	TokenURL            string            `json:"token_url"`
	ClientID            string            `json:"client_id"`
	ClientSecret        string            `json:"client_secret"`
	Scopes              []string          `json:"scopes,omitempty"`
	ExtraParams         map[string]string `json:"extra_params,omitempty"`
	ExpiryMarginSeconds int64             `json:"expiry_margin_seconds,omitempty"`
}

// OAuthAuthFactory implements plugins.Factory so that OAuthClientCredentialsPlugin
// can be configured entirely from the OPA YAML/JSON config file.
//
// Register it once at startup:
//
//	runtime.RegisterPlugin("my_oauth", &httpdata.OAuthAuthFactory{})
//
// Then add a matching section under plugins: in the OPA config:
//
//	plugins:
//	  my_oauth:
//	    token_url: https://auth.example.com/oauth/token
//	    client_id: my-client-id
//	    client_secret: "${CLIENT_SECRET}"
//	    scopes:
//	      - read:data
//	    extra_params:
//	      audience: https://api.example.com
//	    expiry_margin_seconds: 30
//
// Any service may then reference the plugin by name:
//
//	services:
//	  - name: myapi
//	    url: https://api.example.com
//	    credentials:
//	      plugin: my_oauth
type OAuthAuthFactory struct{}

// Validate parses and validates the raw plugin config bytes.
// It returns an OAuthAuthConfig value (not a pointer) on success.
func (f *OAuthAuthFactory) Validate(_ *plugins.Manager, config []byte) (any, error) {
	var cfg OAuthAuthConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, fmt.Errorf("OAuthAuthFactory: failed to parse config: %w", err)
	}
	if cfg.TokenURL == "" {
		return nil, fmt.Errorf("OAuthAuthFactory: missing required field 'token_url'")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("OAuthAuthFactory: missing required field 'client_id'")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("OAuthAuthFactory: missing required field 'client_secret'")
	}
	return cfg, nil
}

// New constructs a new OAuthClientCredentialsPlugin from a validated config.
// If expiry_margin_seconds is not set (or ≤ 0), it defaults to 30 seconds.
func (f *OAuthAuthFactory) New(_ *plugins.Manager, config any) plugins.Plugin {
	cfg := config.(OAuthAuthConfig)
	margin := time.Duration(cfg.ExpiryMarginSeconds) * time.Second
	if margin <= 0 {
		margin = 30 * time.Second
	}
	return &OAuthClientCredentialsPlugin{
		TokenURL:     cfg.TokenURL,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       cfg.Scopes,
		ExtraParams:  cfg.ExtraParams,
		ExpiryMargin: margin,
	}
}
