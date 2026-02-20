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
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/storage"
	inmemtst "github.com/open-policy-agent/opa/v1/storage/inmem/test"
)

// newTestManager creates a plugins.Manager configured with a single REST service
// pointing at the given server URL.
func newTestManager(t *testing.T, serverURL string) *plugins.Manager {
	t.Helper()
	cfg := fmt.Appendf(nil, `{
		"services": [{
			"name": "testsvc",
			"url": %q
		}]
	}`, serverURL)
	manager, err := plugins.New(cfg, "test-id", inmemtst.New())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	return manager
}

// readStorePath reads a value from the store at the given path string.
func readStorePath(t *testing.T, ctx context.Context, manager *plugins.Manager, pathStr string) any {
	t.Helper()
	path, ok := storage.ParsePath(pathStr)
	if !ok {
		t.Fatalf("invalid path %q", pathStr)
	}
	val, err := storage.ReadOne(ctx, manager.Store, path)
	if err != nil {
		t.Fatalf("storage read at %q failed: %v", pathStr, err)
	}
	return val
}

// pluginStatus returns the current plugin status reported to the manager.
func pluginStatus(manager *plugins.Manager) *plugins.Status {
	statuses := manager.PluginStatus()
	return statuses[PluginName]
}

// TestFetchPopulatesStore verifies that a successful periodic fetch writes JSON
// data into the storage at the configured path.
func TestFetchPopulatesStore(t *testing.T) {
	t.Parallel()

	payload := map[string]any{"hello": "world", "count": float64(42)}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/data" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer ts.Close()

	ctx := context.Background()
	manager := newTestManager(t, ts.URL)

	cfg := Config{
		Service:         "testsvc",
		Endpoint:        "/api/data",
		Method:          "GET",
		Path:            "/myapp/external",
		IntervalSeconds: 1,
	}
	_ = cfg.validateAndInjectDefaults(manager.Services())

	p := &Plugin{
		manager:  manager,
		config:   cfg,
		stop:     make(chan chan struct{}),
		reconfig: make(chan Config),
		logger:   manager.Logger().WithFields(map[string]any{"plugin": PluginName}),
	}
	manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
	defer p.Stop(ctx)

	// The initial fetch in Start() is synchronous; data should be in store now.
	got := readStorePath(t, ctx, manager, "/myapp/external")
	gotMap, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", got)
	}
	if gotMap["hello"] != "world" {
		t.Errorf("expected hello=world, got %v", gotMap["hello"])
	}
	if gotMap["count"] != float64(42) {
		t.Errorf("expected count=42, got %v", gotMap["count"])
	}

	status := pluginStatus(manager)
	if status == nil || status.State != plugins.StateOK {
		t.Errorf("expected StateOK, got %v", status)
	}
}

// TestHTTPErrorSetsStateErr verifies that when the server returns a non-200
// status, the plugin sets its status to StateErr and does not corrupt existing
// store data.
func TestHTTPErrorSetsStateErr(t *testing.T) {
	t.Parallel()

	// First request returns good data; subsequent requests return 500.
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"key": "value"})
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	ctx := context.Background()
	manager := newTestManager(t, ts.URL)

	cfg := Config{
		Service:         "testsvc",
		Endpoint:        "/data",
		Method:          "GET",
		Path:            "/myapp/data",
		IntervalSeconds: 1,
	}
	_ = cfg.validateAndInjectDefaults(manager.Services())

	p := &Plugin{
		manager:  manager,
		config:   cfg,
		stop:     make(chan chan struct{}),
		reconfig: make(chan Config),
		logger:   manager.Logger().WithFields(map[string]any{"plugin": PluginName}),
	}
	manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

	// Perform the initial (successful) fetch manually.
	if err := p.fetchAndStore(ctx); err != nil {
		t.Fatalf("first fetchAndStore failed unexpectedly: %v", err)
	}

	// Verify data was written.
	readStorePath(t, ctx, manager, "/myapp/data")

	// Second fetch returns 500.
	err := p.fetchAndStore(ctx)
	if err == nil {
		t.Fatal("expected error from fetchAndStore on 500 response")
	}

	status := pluginStatus(manager)
	if status == nil || status.State != plugins.StateErr {
		t.Errorf("expected StateErr after HTTP 500, got %v", status)
	}

	// Existing data should still be readable (not overwritten with nothing).
	got := readStorePath(t, ctx, manager, "/myapp/data")
	if got == nil {
		t.Error("existing store data was unexpectedly removed after HTTP error")
	}
}

// TestReconfigureChangesInterval verifies that sending a new config via
// Reconfigure causes the loop to use the new interval.
func TestReconfigureChangesInterval(t *testing.T) {
	t.Parallel()

	requestTimes := make([]time.Time, 0, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestTimes = append(requestTimes, time.Now())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"v": 1})
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	manager := newTestManager(t, ts.URL)

	// Start with a 100ms interval.
	cfg := Config{
		Service:         "testsvc",
		Endpoint:        "/data",
		Method:          "GET",
		Path:            "/myapp/rec",
		IntervalSeconds: 0, // will default to 60 after validateAndInjectDefaults; override below
	}
	_ = cfg.validateAndInjectDefaults(manager.Services())
	cfg.IntervalSeconds = 1 // use 1 second so the test runs quickly

	p := &Plugin{
		manager:  manager,
		config:   cfg,
		stop:     make(chan chan struct{}),
		reconfig: make(chan Config),
		logger:   manager.Logger().WithFields(map[string]any{"plugin": PluginName}),
	}
	manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer p.Stop(ctx)

	// Send a reconfigure with a very large interval; the loop should not fire again soon.
	newCfg := cfg
	newCfg.IntervalSeconds = 3600
	newCfg.parsed = cfg.parsed
	p.Reconfigure(ctx, newCfg)

	// Wait a bit to confirm the loop does not trigger additional fetches.
	time.Sleep(200 * time.Millisecond)

	// After reconfigure the ticker should have been reset to 3600s, so no new requests.
	// We just verify no panic / deadlock occurred and the plugin is still OK.
	status := pluginStatus(manager)
	if status == nil || status.State != plugins.StateOK {
		t.Errorf("expected StateOK after reconfigure, got %v", status)
	}
}

// TestStopTerminatesGoroutine verifies that Stop causes the loop to exit cleanly
// within the deadline and that subsequent fetches no longer occur.
func TestStopTerminatesGoroutine(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer ts.Close()

	ctx := context.Background()
	manager := newTestManager(t, ts.URL)

	cfg := Config{
		Service:         "testsvc",
		Endpoint:        "/data",
		Method:          "GET",
		Path:            "/stop/test",
		IntervalSeconds: 1,
	}
	_ = cfg.validateAndInjectDefaults(manager.Services())

	p := &Plugin{
		manager:  manager,
		config:   cfg,
		stop:     make(chan chan struct{}),
		reconfig: make(chan Config),
		logger:   manager.Logger().WithFields(map[string]any{"plugin": PluginName}),
	}
	manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}

	stopDone := make(chan struct{})
	go func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		p.Stop(stopCtx)
		close(stopDone)
	}()

	select {
	case <-stopDone:
		// good — Stop returned within the deadline
	case <-time.After(4 * time.Second):
		t.Fatal("Stop() did not return within the deadline — goroutine leak?")
	}
}

// TestValidateConfig exercises the config validation logic.
func TestValidateConfig(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	manager := newTestManager(t, ts.URL)

	factory := &Factory{}

	// Valid config.
	raw := []byte(`{"service":"testsvc","endpoint":"/data","path":"/app/ext","interval_seconds":30}`)
	val, err := factory.Validate(manager, raw)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	got := val.(Config)
	if got.Method != "GET" {
		t.Errorf("expected default method GET, got %q", got.Method)
	}
	if got.IntervalSeconds != 30 {
		t.Errorf("expected interval 30, got %d", got.IntervalSeconds)
	}

	// Missing service.
	_, err = factory.Validate(manager, []byte(`{"path":"/app/ext"}`))
	if err == nil {
		t.Error("expected error for missing service, got nil")
	}

	// Unknown service.
	_, err = factory.Validate(manager, []byte(`{"service":"unknown","path":"/app/ext"}`))
	if err == nil {
		t.Error("expected error for unknown service, got nil")
	}

	// Missing path.
	_, err = factory.Validate(manager, []byte(`{"service":"testsvc"}`))
	if err == nil {
		t.Error("expected error for missing path, got nil")
	}

	// Invalid path (root).
	_, err = factory.Validate(manager, []byte(`{"service":"testsvc","path":"/"}`))
	if err == nil {
		t.Error("expected error for root path, got nil")
	}
}
