// Package version provides version information for my-custom-eopa.
package version

import (
	"fmt"
	"runtime"
)

// Version information - set via ldflags at build time
var (
	// Version is the semantic version of my-custom-eopa
	Version = "dev"

	// Commit is the git commit hash
	Commit = "unknown"

	// BuildDate is the build timestamp
	BuildDate = "unknown"

	// CapabilitiesVersion matches the capabilities.json version
	CapabilitiesVersion = "1.0.0"
)

// Info returns formatted version information
func Info() string {
	return fmt.Sprintf(`my-custom-eopa:
  Version:      %s
  Capabilities: %s
  Commit:       %s
  Built:        %s
  Go:           %s
  Platform:     %s/%s`,
		Version,
		CapabilitiesVersion,
		Commit,
		BuildDate,
		runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH,
	)
}
