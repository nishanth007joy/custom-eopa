// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package httpdata

// This file provides two custom HTTPAuthPlugin implementations that can be
// registered with the plugin manager and referenced from service config via
//
//   credentials:
//     plugin: "<registered-name>"
//
// Both types also satisfy plugins.Plugin so they can be registered with
// manager.Register(name, plugin).
//
// Typical embedder usage:
//
//   mgr, _ := plugins.New(opaCfg, "id", store)
//   mgr.Register("my_headers_auth", &HeadersAuthPlugin{
//       Headers: map[string]string{"X-Api-Key": "secret"},
//   })
//   // OPA service config: credentials: { plugin: "my_headers_auth" }

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/open-policy-agent/opa/v1/plugins/rest"
)

// ────────────────────────────────────────────────────────────
// HeadersAuthPlugin
// ────────────────────────────────────────────────────────────

// HeadersAuthPlugin injects a fixed set of HTTP headers into every outgoing
// request.  It is useful for static credentials such as API keys or custom
// token schemes that are not covered by OPA's built-in auth types.
//
// Register it with the plugin manager and reference it by name in the service
// config:
//
//   manager.Register("my_headers_auth", &HeadersAuthPlugin{
//       Headers: map[string]string{
//           "X-Api-Key":  "supersecret",
//           "X-Tenant":   "acme",
//       },
//   })
type HeadersAuthPlugin struct {
	// Headers maps header names to their values. All entries are added to
	// every request produced by the service this plugin is attached to.
	Headers map[string]string
}

// NewClient returns a standard HTTP client configured from the service TLS
// settings.  The plugin itself does not modify the transport.
func (p *HeadersAuthPlugin) NewClient(c rest.Config) (*http.Client, error) {
	tlsCfg, err := rest.DefaultTLSConfig(c)
	if err != nil {
		return nil, fmt.Errorf("HeadersAuthPlugin: TLS config error: %w", err)
	}
	timeout := int64(10)
	if c.ResponseHeaderTimeoutSeconds != nil {
		timeout = *c.ResponseHeaderTimeoutSeconds
	}
	return rest.DefaultRoundTripperClient(tlsCfg, timeout), nil
}

// Prepare adds all configured headers to req.
func (p *HeadersAuthPlugin) Prepare(req *http.Request) error {
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	return nil
}

// Start implements plugins.Plugin (no-op).
func (*HeadersAuthPlugin) Start(context.Context) error { return nil }

// Stop implements plugins.Plugin (no-op).
func (*HeadersAuthPlugin) Stop(context.Context) {}

// Reconfigure implements plugins.Plugin (no-op — headers are set at construction).
func (*HeadersAuthPlugin) Reconfigure(context.Context, any) {}

// ────────────────────────────────────────────────────────────
// HMACAuthPlugin
// ────────────────────────────────────────────────────────────

const (
	defaultHMACHeader    = "X-Signature"
	defaultHMACTimestamp = "X-Timestamp"
)

// HMACAuthPlugin signs each outgoing request with an HMAC-SHA256 signature
// and attaches it as an HTTP header.  The signed payload is:
//
//	<METHOD>\n<URL-path>\n<RFC3339-timestamp>\n<hex(SHA256(body))>
//
// Two headers are added to every request:
//   - SignatureHeader (default "X-Signature"): hex-encoded HMAC-SHA256
//   - TimestampHeader (default "X-Timestamp"):  RFC3339 timestamp used in the
//     signature so the server can validate freshness and replay-resistance.
//
// Register it with the plugin manager and reference it by name in the service
// config:
//
//	manager.Register("my_hmac_auth", &HMACAuthPlugin{
//	    Secret:          "my-shared-secret",
//	    SignatureHeader: "X-Hub-Signature-256",
//	    TimestampHeader: "X-Request-Time",
//	})
type HMACAuthPlugin struct {
	// Secret is the shared HMAC key (required).
	Secret string

	// SignatureHeader is the name of the header that carries the hex-encoded
	// HMAC-SHA256 digest.  Defaults to "X-Signature".
	SignatureHeader string

	// TimestampHeader is the name of the header that carries the RFC3339
	// timestamp included in the signed payload.  Defaults to "X-Timestamp".
	TimestampHeader string

	// now is a hook for deterministic timestamps in tests.
	now func() time.Time
}

// NewClient returns a standard HTTP client configured from the service TLS
// settings.
func (p *HMACAuthPlugin) NewClient(c rest.Config) (*http.Client, error) {
	tlsCfg, err := rest.DefaultTLSConfig(c)
	if err != nil {
		return nil, fmt.Errorf("HMACAuthPlugin: TLS config error: %w", err)
	}
	timeout := int64(10)
	if c.ResponseHeaderTimeoutSeconds != nil {
		timeout = *c.ResponseHeaderTimeoutSeconds
	}
	return rest.DefaultRoundTripperClient(tlsCfg, timeout), nil
}

// Prepare signs the request and adds the signature and timestamp headers.
// The request body is read, hashed (SHA256), and the body content is restored
// so the transport can send it normally.
func (p *HMACAuthPlugin) Prepare(req *http.Request) error {
	if p.Secret == "" {
		return fmt.Errorf("HMACAuthPlugin: Secret must not be empty")
	}

	sigHeader := p.SignatureHeader
	if sigHeader == "" {
		sigHeader = defaultHMACHeader
	}
	tsHeader := p.TimestampHeader
	if tsHeader == "" {
		tsHeader = defaultHMACTimestamp
	}

	nowFn := p.now
	if nowFn == nil {
		nowFn = time.Now
	}
	ts := nowFn().UTC().Format(time.RFC3339)

	// Read and restore the body.
	var bodyBytes []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("HMACAuthPlugin: failed to read request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Build the signed payload.
	bodyHash := sha256.Sum256(bodyBytes)
	payload := fmt.Sprintf("%s\n%s\n%s\n%s",
		req.Method,
		req.URL.RequestURI(),
		ts,
		hex.EncodeToString(bodyHash[:]),
	)

	mac := hmac.New(sha256.New, []byte(p.Secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	req.Header.Set(sigHeader, sig)
	req.Header.Set(tsHeader, ts)
	return nil
}

// Start implements plugins.Plugin (no-op).
func (*HMACAuthPlugin) Start(context.Context) error { return nil }

// Stop implements plugins.Plugin (no-op).
func (*HMACAuthPlugin) Stop(context.Context) {}

// Reconfigure implements plugins.Plugin (no-op — config is set at construction).
func (*HMACAuthPlugin) Reconfigure(context.Context, any) {}
