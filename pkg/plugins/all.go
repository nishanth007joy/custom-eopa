// Package plugins provides the plugin registry for my-custom-eopa.
package plugins

import (
	eopa_plugins "github.com/open-policy-agent/eopa/pkg/plugins"
	"github.com/open-policy-agent/opa/v1/plugins"
	"github.com/open-policy-agent/opa/v1/runtime"

	"github.com/yourorg/my-custom-eopa/pkg/plugins/mydata"
	"github.com/yourorg/my-custom-eopa/pkg/plugins/s3data"
)

func init() {
	// Register custom plugins globally with the OPA runtime
	// This makes them available to the run command
	runtime.RegisterPlugin(mydata.Name, mydata.Factory())
	runtime.RegisterPlugin(s3data.Name, s3data.Factory())
}

// All returns all available plugins, combining EOPA's plugins with custom ones.
// This function can be used when creating a custom Manager to include custom plugins.
func All() map[string]plugins.Factory {
	// Start with EOPA's built-in plugins
	all := eopa_plugins.All()

	// Add custom plugins
	all[mydata.Name] = mydata.Factory()
	all[s3data.Name] = s3data.Factory()

	return all
}
