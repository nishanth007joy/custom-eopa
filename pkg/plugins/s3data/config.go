package s3data

import (
	"errors"
	"time"
)

// Config holds the configuration for the s3data plugin
type Config struct {
	// Bucket is the S3 bucket name
	Bucket string `json:"bucket"`

	// Key is the S3 object key (path to the file)
	Key string `json:"key"`

	// Region is the AWS region (optional if using IRSA with region auto-detection)
	Region string `json:"region,omitempty"`

	// Path is the storage path where fetched data will be stored in OPA
	// Example: "/s3data/policies" makes data available at data.s3data.policies
	Path string `json:"path"`

	// PollInterval is how often to refresh the data (e.g., "30s", "5m")
	PollInterval string `json:"poll_interval,omitempty"`

	// Endpoint is a custom S3 endpoint (for S3-compatible storage like MinIO)
	Endpoint string `json:"endpoint,omitempty"`

	// UsePathStyle enables path-style addressing (required for some S3-compatible storage)
	UsePathStyle bool `json:"use_path_style,omitempty"`

	// RoleARN is an optional IAM role ARN to assume (IRSA handles this automatically if not set)
	RoleARN string `json:"role_arn,omitempty"`

	// parsed values
	pollInterval time.Duration
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Bucket == "" {
		return errors.New("s3data: bucket is required")
	}

	if c.Key == "" {
		return errors.New("s3data: key is required")
	}

	if c.Path == "" {
		return errors.New("s3data: path is required")
	}

	// Parse poll interval
	if c.PollInterval != "" {
		d, err := time.ParseDuration(c.PollInterval)
		if err != nil {
			return errors.New("s3data: invalid poll_interval: " + err.Error())
		}
		if d < time.Second {
			return errors.New("s3data: poll_interval must be at least 1s")
		}
		c.pollInterval = d
	} else {
		c.pollInterval = 60 * time.Second // default
	}

	return nil
}

// GetPollInterval returns the parsed poll interval
func (c *Config) GetPollInterval() time.Duration {
	if c.pollInterval == 0 {
		return 60 * time.Second
	}
	return c.pollInterval
}