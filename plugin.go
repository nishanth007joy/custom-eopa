// Copyright 2024 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package httpdata implements a plugin that periodically fetches JSON data from
// a configured HTTP service and writes it into OPA's storage, making it
// available in Rego as data.<path>.
package httpdata

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/open-policy-agent/opa/v1/logging"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/storage"
)

// PluginName is the name used to register this plugin with the manager.
const PluginName = "httpdata"

const defaultIntervalSeconds = int64(60)
const defaultMethod = "GET"

// Config holds the configuration for the httpdata plugin.
type Config struct {
	// Service is the name of a configured OPA REST service (required).
	Service string `json:"service"`
	// Endpoint is the HTTP path on the service, e.g. "/api/v1/data".
	Endpoint string `json:"endpoint"`
	// Method is the HTTP method to use. Defaults to "GET".
	Method string `json:"method"`
	// Path is the storage path where fetched data will be written, e.g. "/myapp/external".
	Path string `json:"path"`
	// IntervalSeconds is the refresh interval in seconds. Defaults to 60.
	IntervalSeconds int64 `json:"interval_seconds"`

	// parsed is the parsed storage path (derived from Path).
	parsed storage.Path
}

func (c *Config) validateAndInjectDefaults(services []string) error {
	if c.Service == "" {
		return fmt.Errorf("httpdata plugin: missing required field 'service'")
	}

	if !slices.Contains(services, c.Service) {
		return fmt.Errorf("httpdata plugin: unknown service %q", c.Service)
	}

	if c.Path == "" {
		return fmt.Errorf("httpdata plugin: missing required field 'path'")
	}

	parsed, ok := storage.ParsePath(c.Path)
	if !ok {
		return fmt.Errorf("httpdata plugin: invalid storage path %q", c.Path)
	}
	if len(parsed) == 0 {
		return fmt.Errorf("httpdata plugin: storage path must not be root")
	}
	c.parsed = parsed

	if c.Method == "" {
		c.Method = defaultMethod
	}

	if c.IntervalSeconds <= 0 {
		c.IntervalSeconds = defaultIntervalSeconds
	}

	return nil
}

// Factory implements plugins.Factory for the httpdata plugin.
type Factory struct{}

// Validate parses and validates the raw plugin config bytes.
func (f *Factory) Validate(manager *plugins.Manager, config []byte) (any, error) {
	var cfg Config
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, fmt.Errorf("httpdata plugin: failed to parse config: %w", err)
	}
	if err := cfg.validateAndInjectDefaults(manager.Services()); err != nil {
		return nil, err
	}
	return cfg, nil
}

// New constructs a new Plugin instance from a validated config.
func (f *Factory) New(manager *plugins.Manager, config any) plugins.Plugin {
	cfg := config.(Config)
	p := &Plugin{
		manager:  manager,
		config:   cfg,
		stop:     make(chan chan struct{}),
		reconfig: make(chan Config),
		logger:   manager.Logger().WithFields(map[string]any{"plugin": PluginName}),
	}
	manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
	return p
}

// Plugin periodically fetches JSON data from a REST service and stores it.
type Plugin struct {
	manager  *plugins.Manager
	config   Config
	stop     chan chan struct{}
	reconfig chan Config
	logger   logging.Logger
}

// Start performs an initial fetch and then spawns the refresh loop.
func (p *Plugin) Start(ctx context.Context) error {
	p.logger.Info("Starting httpdata plugin.")
	if err := p.fetchAndStore(ctx); err != nil {
		p.logger.Error("httpdata plugin: initial fetch failed: %v", err)
	}
	go p.loop(ctx)
	return nil
}

// Stop signals the loop goroutine to exit and waits for it to finish.
func (p *Plugin) Stop(ctx context.Context) {
	p.logger.Info("Stopping httpdata plugin.")
	done := make(chan struct{})
	p.stop <- done
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Reconfigure applies a new configuration to the running plugin.
func (p *Plugin) Reconfigure(_ context.Context, config any) {
	cfg := config.(Config)
	p.reconfig <- cfg
}

func (p *Plugin) loop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(p.config.IntervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.fetchAndStore(ctx); err != nil {
				p.logger.Error("httpdata plugin: fetch failed: %v", err)
			}

		case cfg := <-p.reconfig:
			p.config = cfg
			ticker.Reset(time.Duration(cfg.IntervalSeconds) * time.Second)

		case done := <-p.stop:
			done <- struct{}{}
			return
		}
	}
}

func (p *Plugin) fetchAndStore(ctx context.Context) error {
	resp, err := p.manager.Client(p.config.Service).Do(ctx, p.config.Method, p.config.Endpoint)
	if err != nil {
		p.manager.UpdatePluginStatus(PluginName, &plugins.Status{
			State:   plugins.StateErr,
			Message: fmt.Sprintf("HTTP request failed: %v", err),
		})
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		msg := fmt.Sprintf("unexpected HTTP status %d: %s", resp.StatusCode, string(body))
		p.manager.UpdatePluginStatus(PluginName, &plugins.Status{
			State:   plugins.StateErr,
			Message: msg,
		})
		return fmt.Errorf("httpdata plugin: %s", msg)
	}

	var data any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		p.manager.UpdatePluginStatus(PluginName, &plugins.Status{
			State:   plugins.StateErr,
			Message: fmt.Sprintf("JSON decode failed: %v", err),
		})
		return fmt.Errorf("httpdata plugin: JSON decode failed: %w", err)
	}

	path := p.config.parsed

	err = storage.Txn(ctx, p.manager.Store, storage.WriteParams, func(txn storage.Transaction) error {
		if err := storage.MakeDir(ctx, p.manager.Store, txn, path[:len(path)-1]); err != nil {
			return err
		}
		return p.manager.Store.Write(ctx, txn, storage.AddOp, path, data)
	})
	if err != nil {
		p.manager.UpdatePluginStatus(PluginName, &plugins.Status{
			State:   plugins.StateErr,
			Message: fmt.Sprintf("storage write failed: %v", err),
		})
		return fmt.Errorf("httpdata plugin: storage write failed: %w", err)
	}

	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateOK})
	return nil
}
