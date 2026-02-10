
package mydata

import (
	"errors"
	"time"
)

// Config holds the configuration for the mydata plugin
type Config struct {
	// Endpoint is the URL of the data source API
	Endpoint string `json:"endpoint"`

	// APIKey is the authentication key for the data source
	APIKey string `json:"api_key,omitempty"`

	// Path is the storage path where fetched data will be stored
	// Example: "/mydata/users" makes data available at data.mydata.users
	Path string `json:"path"`

	// PollInterval is how often to refresh the data (e.g., "30s", "5m")
	PollInterval string `json:"poll_interval,omitempty"`

	// Headers are additional HTTP headers to send with requests
	Headers map[string]string `json:"headers,omitempty"`

	// Timeout is the request timeout (e.g., "10s")
	Timeout string `json:"timeout,omitempty"`

	// SkipTLSVerify disables TLS certificate verification (not recommended for production)
	SkipTLSVerify bool `json:"skip_tls_verify,omitempty"`

	// parsed values
	pollInterval time.Duration
	timeout      time.Duration
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Endpoint == "" {
		return errors.New("mydata: endpoint is required")
	}

	if c.Path == "" {
		return errors.New("mydata: path is required")
	}

	// Parse poll interval
	if c.PollInterval != "" {
		d, err := time.ParseDuration(c.PollInterval)
		if err != nil {
			return errors.New("mydata: invalid poll_interval: " + err.Error())
		}
		if d < time.Second {
			return errors.New("mydata: poll_interval must be at least 1s")
		}
		c.pollInterval = d
	} else {
		c.pollInterval = 30 * time.Second // default
	}

	// Parse timeout
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil {
			return errors.New("mydata: invalid timeout: " + err.Error())
		}
		c.timeout = d
	} else {
		c.timeout = 10 * time.Second // default
	}

	return nil
}

// GetPollInterval returns the parsed poll interval
func (c *Config) GetPollInterval() time.Duration {
	if c.pollInterval == 0 {
		return 30 * time.Second
	}
	return c.pollInterval
}

// GetTimeout returns the parsed timeout
func (c *Config) GetTimeout() time.Duration {
	if c.timeout == 0 {
		return 10 * time.Second
	}
	return c.timeout
}
