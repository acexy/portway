// Package configtemplate embeds the annotated configuration files distributed
// with the same Portway build.
package configtemplate

import _ "embed"

var (
	//go:embed client.yaml
	client []byte
	//go:embed server.yaml
	server []byte
)

// Client returns an independent copy of the full client configuration template.
func Client() []byte {
	return append([]byte(nil), client...)
}

// Server returns an independent copy of the full server configuration template.
func Server() []byte {
	return append([]byte(nil), server...)
}
