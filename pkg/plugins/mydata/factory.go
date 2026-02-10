// Package mydata provides a custom data plugin for fetching data from external sources.
package mydata

import (
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/util"
)

// Name is the registered name of this plugin
const Name = "mydata"

type factory struct{}

// Factory returns a new plugin factory for the mydata plugin
func Factory() plugins.Factory {
	return &factory{}
}

// New creates a new instance of the mydata plugin
func (f *factory) New(m *plugins.Manager, config interface{}) plugins.Plugin {
	c := config.(Config)
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
