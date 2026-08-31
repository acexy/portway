// Package configgenerator writes safe starter configuration files.
package gen

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	configtemplate "github.com/acexy/portway/config"
	portwayconfig "github.com/acexy/portway/internal/config"
)

// Target identifies the generated process configuration.
type Target uint8

const (
	// TargetClient generates client.yaml.
	TargetClient Target = iota
	// TargetServer generates server.yaml.
	TargetServer
)

// ParseMode accepts the optional positional "full" selector.
func ParseMode(arguments []string) (bool, error) {
	if len(arguments) == 0 {
		return false, nil
	}
	if len(arguments) == 1 && arguments[0] == "full" {
		return true, nil
	}
	return false, errors.New("expected no argument or the single argument \"full\"")
}

const clientMinimal = `# Minimal Portway client configuration.
# Full reference: https://github.com/acexy/portway/tree/main/config

transport:
  type: tcp
  server_address: 127.0.0.1:7000

authentication:
  token: PORTWAY_TOKEN_REQUIRED

proxies:
  - name: ssh
    type: tcp
    local:
      ip: 127.0.0.1
      port: 22
    public:
      port: 22022
`

const clientTokenPlaceholder = "PORTWAY_TOKEN_REQUIRED"

const serverMinimal = `# Minimal Portway server configuration.
# Full reference: https://github.com/acexy/portway/tree/main/config

transport:
  type: tcp
  listen_address: 0.0.0.0:7000

authentication:
  # An empty value generates a Token at startup and reuses it during hot reload.
  # Save the logged Token here before restarting the server.
  shared_token: ""
`

// Generate writes one minimal or full configuration without replacing an
// existing file. Configuration files use owner-only permissions because they
// contain or will contain credentials.
func Generate(target Target, full bool) (string, error) {
	path, content, err := generatedContent(target, full)
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("refusing to overwrite existing configuration %q", path)
		}
		return "", fmt.Errorf("create configuration %q: %w", path, err)
	}
	removeIncomplete := true
	defer func() {
		if removeIncomplete {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write configuration %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close configuration %q: %w", path, err)
	}
	removeIncomplete = false
	return path, nil
}

func generatedContent(target Target, full bool) (string, []byte, error) {
	switch target {
	case TargetClient:
		token, err := portwayconfig.GenerateToken()
		if err != nil {
			return "", nil, err
		}
		content := []byte(clientMinimal)
		if full {
			content = configtemplate.Client()
		}
		if !bytes.Contains(content, []byte(clientTokenPlaceholder)) {
			return "", nil, errors.New("client configuration Token placeholder is missing")
		}
		content = bytes.ReplaceAll(content, []byte(clientTokenPlaceholder), []byte(token))
		return "client.yaml", content, nil
	case TargetServer:
		if full {
			return "server.yaml", configtemplate.Server(), nil
		}
		return "server.yaml", []byte(serverMinimal), nil
	default:
		return "", nil, errors.New("unsupported configuration target")
	}
}
