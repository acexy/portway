package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadClient loads a client configuration and overlays it on safe defaults.
func LoadClient(path string, allowMissing bool) (ClientConfig, error) {
	configuration := DefaultClient()
	if err := loadYAML(path, allowMissing, &configuration); err != nil {
		return ClientConfig{}, err
	}
	if err := validateClient(configuration); err != nil {
		return ClientConfig{}, err
	}
	return configuration, nil
}

// LoadServer loads a server configuration and overlays it on safe defaults.
func LoadServer(path string, allowMissing bool) (ServerConfig, error) {
	configuration := DefaultServer()
	initialDigest, initialExists, err := configurationFileDigest(path, allowMissing)
	if err != nil {
		return ServerConfig{}, err
	}
	if err := loadYAML(path, allowMissing, &configuration); err != nil {
		return ServerConfig{}, err
	}
	if err := validateServer(configuration); err != nil {
		return ServerConfig{}, err
	}
	if _, err := os.Stat(path); err == nil {
		configuration.SourcePath = path
	} else if !allowMissing || !errors.Is(err, os.ErrNotExist) {
		return ServerConfig{}, fmt.Errorf("stat configuration %q: %w", path, err)
	}
	before, err := serverSourceManifest(configuration)
	if err != nil {
		return ServerConfig{}, err
	}
	if initialExists && before.mainDigest != initialDigest {
		return ServerConfig{}, errors.New("configuration files changed while loading")
	}
	if err := loadServerAuthenticationFiles(&configuration); err != nil {
		return ServerConfig{}, err
	}
	if err := validateProxyMirrorConfiguration(configuration); err != nil {
		return ServerConfig{}, err
	}
	if err := validateConfiguredPublicSchemeAvailability(configuration); err != nil {
		return ServerConfig{}, err
	}
	if err := validateForwardConfiguration(configuration); err != nil {
		return ServerConfig{}, err
	}
	after, err := serverSourceManifest(configuration)
	if err != nil {
		return ServerConfig{}, err
	}
	if before.digest != after.digest {
		return ServerConfig{}, errors.New("configuration files changed while loading")
	}
	configuration.SourceDigest = hex.EncodeToString(after.digest[:])
	return configuration, nil
}

func loadYAML(path string, allowMissing bool, destination any) error {
	data, err := readConfigurationFile(path)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return decodeYAML(path, bytes.NewReader(data), destination)
}

func readConfigurationFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configuration %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat configuration %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("configuration %q is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigurationFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read configuration %q: %w", path, err)
	}
	if len(data) > maxConfigurationFileBytes {
		return nil, fmt.Errorf(
			"configuration %q exceeds %d bytes",
			path,
			maxConfigurationFileBytes,
		)
	}
	return data, nil
}

func decodeYAML(path string, reader io.Reader, destination any) error {
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode configuration %q: %w", path, err)
	}

	var trailingDocument any
	if err := decoder.Decode(&trailingDocument); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode configuration %q: multiple YAML documents are not allowed", path)
		}
		return fmt.Errorf("decode configuration %q: %w", path, err)
	}
	return nil
}

func loadAuthenticationYAML(path string, destination any) error {
	data, err := readAuthenticationFile(path)
	if err != nil {
		return err
	}
	return decodeYAML(path, bytes.NewReader(data), destination)
}
