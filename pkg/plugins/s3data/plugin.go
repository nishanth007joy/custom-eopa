package s3data

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	inmem "github.com/open-policy-agent/eopa/pkg/storage"
	"github.com/open-policy-agent/opa/v1/logging"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/storage"
)

// Plugin implements the s3data data source plugin
type Plugin struct {
	manager  *plugins.Manager
	config   Config
	log      logging.Logger
	stop     chan struct{}
	s3Client *s3.Client
}

// Start initializes and starts the plugin
func (p *Plugin) Start(ctx context.Context) error {
	p.log.Info("Starting s3data plugin", "bucket", p.config.Bucket, "key", p.config.Key, "path", p.config.Path)

	// Initialize S3 client with IRSA support
	if err := p.initS3Client(ctx); err != nil {
		return fmt.Errorf("failed to initialize S3 client: %w", err)
	}

	// Fetch initial data
	if err := p.fetchAndStore(ctx); err != nil {
		p.log.Warn("Failed to fetch initial data from S3", "error", err)
		// Don't fail startup, just log the error
	}

	// Start background polling
	go p.pollLoop()

	// Update plugin status
	p.manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateOK})

	return nil
}

// initS3Client initializes the S3 client with IRSA credentials
func (p *Plugin) initS3Client(ctx context.Context) error {
	// Load AWS config - automatically uses IRSA when running in EKS
	// IRSA sets AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE environment variables
	// The SDK's default credential chain handles this automatically
	opts := []func(*config.LoadOptions) error{}

	// Set region if specified
	if p.config.Region != "" {
		opts = append(opts, config.WithRegion(p.config.Region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// If a specific role ARN is provided, assume that role
	if p.config.RoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		creds := stscreds.NewAssumeRoleProvider(stsClient, p.config.RoleARN)
		cfg.Credentials = aws.NewCredentialsCache(creds)
		p.log.Info("Configured to assume role", "role_arn", p.config.RoleARN)
	}

	// Create S3 client options
	s3Opts := []func(*s3.Options){}

	// Custom endpoint for S3-compatible storage
	if p.config.Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(p.config.Endpoint)
		})
		p.log.Info("Using custom S3 endpoint", "endpoint", p.config.Endpoint)
	}

	// Path-style addressing for S3-compatible storage
	if p.config.UsePathStyle {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	p.s3Client = s3.NewFromConfig(cfg, s3Opts...)
	p.log.Info("S3 client initialized successfully")

	return nil
}

// Stop gracefully stops the plugin
func (p *Plugin) Stop(ctx context.Context) {
	p.log.Info("Stopping s3data plugin")
	close(p.stop)
	p.manager.UpdatePluginStatus(Name, &plugins.Status{State: plugins.StateNotReady})
}

// Reconfigure updates the plugin configuration
func (p *Plugin) Reconfigure(ctx context.Context, cfg interface{}) {
	newConfig := cfg.(Config)
	p.log.Info("Reconfiguring s3data plugin", "bucket", newConfig.Bucket, "key", newConfig.Key)

	// Check if S3 client needs to be recreated
	needsNewClient := p.config.Region != newConfig.Region ||
		p.config.Endpoint != newConfig.Endpoint ||
		p.config.RoleARN != newConfig.RoleARN ||
		p.config.UsePathStyle != newConfig.UsePathStyle

	p.config = newConfig

	if needsNewClient {
		if err := p.initS3Client(ctx); err != nil {
			p.log.Error("Failed to reinitialize S3 client", "error", err)
			return
		}
	}

	// Fetch data with new config
	if err := p.fetchAndStore(ctx); err != nil {
		p.log.Warn("Failed to fetch data after reconfigure", "error", err)
	}
}

// pollLoop periodically fetches data from S3
func (p *Plugin) pollLoop() {
	ticker := time.NewTicker(p.config.GetPollInterval())
	defer ticker.Stop()

	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := p.fetchAndStore(ctx); err != nil {
				p.log.Warn("Failed to fetch data during poll", "error", err)
			}
			cancel()
		}
	}
}

// fetchAndStore fetches data from S3 and stores it in OPA
func (p *Plugin) fetchAndStore(ctx context.Context) error {
	data, err := p.fetchData(ctx)
	if err != nil {
		return fmt.Errorf("fetch failed: %w", err)
	}

	if err := p.storeData(ctx, data); err != nil {
		return fmt.Errorf("store failed: %w", err)
	}

	p.log.Debug("Successfully fetched and stored S3 data", "bucket", p.config.Bucket, "key", p.config.Key, "path", p.config.Path)
	return nil
}

// fetchData retrieves data from S3
func (p *Plugin) fetchData(ctx context.Context) (interface{}, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(p.config.Bucket),
		Key:    aws.String(p.config.Key),
	}

	result, err := p.s3Client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 object: %w", err)
	}
	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read S3 object body: %w", err)
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to parse JSON from S3 object: %w", err)
	}

	return data, nil
}

// storeData writes the fetched data to OPA's storage using EOPA's optimized ingestion
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

	// Ensure parent paths exist before writing
	if len(path) > 1 {
		if err := storage.MakeDir(ctx, store, txn, path[:len(path)-1]); err != nil {
			store.Abort(ctx, txn)
			return fmt.Errorf("failed to create parent path: %w", err)
		}
	}

	// Use EOPA's optimized WriteUncheckedTxn for efficient data ingestion
	if err := inmem.WriteUncheckedTxn(ctx, store, txn, storage.ReplaceOp, path, data); err != nil {
		store.Abort(ctx, txn)
		return fmt.Errorf("failed to write data to %v: %w", path, err)
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

	return inmem.WriteUncheckedTxn(ctx, p.manager.Store, txn, storage.ReplaceOp, path, data)
}