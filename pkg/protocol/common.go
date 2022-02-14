package protocol

// KMSProfileSuite is a named kms key profile with key id and type.
type KMSProfileSuite struct {
	Name       string `json:"name"`
	PluginName string `json:"pluginName"`
	ID         string `json:"id"`
}
