package s3data

import (
	"time"

	"github.com/open-policy-agent/opa/v1/storage"
)

const (
	AWSScheme = "s3"
	GCSScheme = "gs"
)

var (
	DefaultRegions = map[string]string{
		AWSScheme: "us-east-1",
		GCSScheme: "auto",
	}
	DefaultEndpoints = map[string]string{
		AWSScheme: "",
		GCSScheme: "https://storage.googleapis.com",
	}
)

// Config represents the configuration of the s3 data plugin
type Config struct {
	URL       string `json:"url"`
	Region    string `json:"region,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	ForcePath bool   `json:"force_path"`

	// RoleARN is an optional IAM role ARN to assume via STS.
	// When running in EKS with IRSA, the default credential chain handles
	// authentication automatically (via AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE).
	// Set this only if you need to assume a different role than the one provided by IRSA.
	RoleARN string `json:"role_arn,omitempty"`

	Interval string `json:"polling_interval,omitempty"` // default 5m, min 10s
	Path     string `json:"path"`

	RegoTransformRule string `json:"rego_transform"`

	// inserted through Validate()
	bucket   string
	filepath string
	region   string
	endpoint string
	path     storage.Path
	interval time.Duration
}

func (c Config) Equal(other Config) bool {
	switch {
	case c.RoleARN != other.RoleARN:
	case c.RegoTransformRule != other.RegoTransformRule:
	case c.ForcePath != other.ForcePath:
	case c.bucket != other.bucket:
	case c.filepath != other.filepath:
	case c.region != other.region:
	case c.endpoint != other.endpoint:
	case c.Interval != other.Interval:
	default:
		return true
	}
	return false
}
