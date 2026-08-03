// Package configgenerator writes safe starter configuration files.
package configgenerator

import (
	"errors"
	"fmt"
	"os"

	configtemplate "github.com/acexy/portway/config"
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
  token: CHANGE_ME_TO_A_RANDOM_TOKEN_AT_LEAST_32_BYTES

proxies:
  - name: ssh
    type: tcp
    local_ip: 127.0.0.1
    local_port: 22
    remote_port: 22022
`

const serverMinimal = `# Minimal Portway server configuration.
# Full reference: https://github.com/acexy/portway/tree/main/config

transport:
  type: tcp
  listen_address: 0.0.0.0:7000

authentication:
  # The generated Token is logged once at startup. Persist it here before restart.
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
		if full {
			return "client.yaml", configtemplate.Client(), nil
		}
		return "client.yaml", []byte(clientMinimal), nil
	case TargetServer:
		if full {
			return "server.yaml", configtemplate.Server(), nil
		}
		return "server.yaml", []byte(serverMinimal), nil
	default:
		return "", nil, errors.New("unsupported configuration target")
	}
}
