package version

var (
	// Version shows the current notation-cose version, optionally with pre-release.
	Version = "v0.3.0-alpha.1"

	// BuildMetadata stores the build metadata.
	BuildMetadata = "unreleased"
)

// GetVersion returns the version string in SemVer 2.
func GetVersion() string {
	if BuildMetadata == "" {
		return Version
	}
	return Version + "+" + BuildMetadata
}
