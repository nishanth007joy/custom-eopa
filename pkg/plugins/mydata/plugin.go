package mydata

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/open-policy-agent/opa/v1/logging"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/storage"
)

// Plugin implements the mydata data source plugin
type Plugin struct {
	manager *plugins.Manager
	config  Config
	log     logging.Logger
	stop    chan struct{}
	client  *http.Client
}

// Start initializes and starts the plugin
func (p *Plugin) Start(ctx context.Context) error {
	p.log.Info("Starting mydata plugin", "endpoint", p.config.Endpoint, "path", p.config.Path)

	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: p.config.SkipTLSVerify,
		},
	}
	p.client = &http.Client{
		Transport: transport,
		Timeout:   p.config.GetTimeout(),
	}

	// Fetch initial data
	if err := p.fetchAndStore(ctx); err != nil {
		p.log.Warn("Failed to fetch initial data", "error", err)
		// Don't fail startup, just log the error
	}

	// Start background polling
	go p.pollLoop()

	// Update plugin status
	p.manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateOK})

	return nil
}

// Stop gracefully stops the plugin
func (p *Plugin) Stop(ctx context.Context) {
	p.log.Info("Stopping mydata plugin")
	close(p.stop)
	p.manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateNotReady})
}

// Reconfigure updates the plugin configuration
func (p *Plugin) Reconfigure(ctx context.Context, config interface{}) {
	newConfig := config.(Config)
	p.log.Info("Reconfiguring mydata plugin", "endpoint", newConfig.Endpoint)
	p.config = newConfig

	// Update client timeout if changed
	p.client.Timeout = p.config.GetTimeout()

	// Fetch data with new config
	if err := p.fetchAndStore(ctx); err != nil {
		p.log.Warn("Failed to fetch data after reconfigure", "error", err)
	}
}

// pollLoop periodically fetches data from the endpoint
func (p *Plugin) pollLoop() {
	ticker := time.NewTicker(p.config.GetPollInterval())
	defer ticker.Stop()

	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), p.config.GetTimeout())
			if err := p.fetchAndStore(ctx); err != nil {
				p.log.Warn("Failed to fetch data during poll", "error", err)
			}
			cancel()
		}
	}
}

// fetchAndStore fetches data from the endpoint and stores it
func (p *Plugin) fetchAndStore(ctx context.Context) error {
	data, err := p.fetchData(ctx)
	if err != nil {
		return fmt.Errorf("fetch failed: %w", err)
	}

	if err := p.storeData(ctx, data); err != nil {
		return fmt.Errorf("store failed: %w", err)
	}

	p.log.Debug("Successfully fetched and stored data", "path", p.config.Path)
	return nil
}

// fetchData retrieves data from the configured endpoint
func (p *Plugin) fetchData(ctx context.Context) (interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.config.Endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	for k, v := range p.config.Headers {
		req.Header.Set(k, v)
	}
	if p.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.config.APIKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return data, nil
}

// storeData writes the fetched data to OPA's storage
func (p *Plugin) storeData(ctx context.Context, data interface{}) error {
	store := p.manager.Store
	path, ok := storage.ParsePath(p.config.Path)
	if !ok {
		return fmt.Errorf("invalid storage path %q", p.config.Path)
	}

	txn, err := store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}

	// Ensure parent paths exist
	if err := storage.MakeDir(ctx, store, txn, path[:len(path)-1]); err != nil {
		store.Abort(ctx, txn)
		return fmt.Errorf("failed to create parent path: %w", err)
	}

	// Write the data
	if err := store.Write(ctx, txn, storage.AddOp, path, data); err != nil {
		// Try replace if add fails (path already exists)
		if err := store.Write(ctx, txn, storage.ReplaceOp, path, data); err != nil {
			store.Abort(ctx, txn)
			return fmt.Errorf("failed to write data: %w", err)
		}
	}

	if err := store.Commit(ctx, txn); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Trigger implements the types.Triggerer interface for manual data refresh
func (p *Plugin) Trigger(ctx context.Context, txn storage.Transaction) error {
	data, err := p.fetchData(ctx)
	if err != nil {
		return err
	}

	path, ok := storage.ParsePath(p.config.Path)
	if !ok {
		return fmt.Errorf("invalid storage path %q", p.config.Path)
	}

	return p.manager.Store.Write(ctx, txn, storage.ReplaceOp, path, data)
}
