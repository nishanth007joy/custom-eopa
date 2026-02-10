// Package s3data provides an S3 data plugin for fetching data from AWS S3 with IRSA support.
package s3data

import (
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/util"
)

// Name is the registered name of this plugin
const Name = "s3data"

type factory struct{}

// Factory returns a new plugin factory for the s3data plugin
func Factory() plugins.Factory {
	return &factory{}
}

// New creates a new instance of the s3data plugin
func (f *factory) New(m *plugins.Manager, cfg interface{}) plugins.Plugin {
	c := cfg.(Config)
	return &Plugin{
		manager: m,
		config:  c,
		log:     m.Logger().WithFields(map[string]interface{}{"plugin": Name}),
		stop:    make(chan struct{}),
	}
}

// Validate validates the plugin configuration
func (f *factory) Validate(m *plugins.Manager, config []byte) (interface{}, error) {
	c := Config{}
	if err := util.Unmarshal(config, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}