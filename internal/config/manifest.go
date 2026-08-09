package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type sourceManifest struct {
	mainDigest [sha256.Size]byte
	digest     [sha256.Size]byte
}

func serverSourceManifest(configuration ServerConfig) (sourceManifest, error) {
	hasher := sha256.New()
	manifest := sourceManifest{}
	if configuration.SourcePath != "" {
		digest, _, err := configurationFileDigest(configuration.SourcePath, false)
		if err != nil {
			return sourceManifest{}, err
		}
		manifest.mainDigest = digest
		hasher.Write([]byte(filepath.Clean(configuration.SourcePath)))
		hasher.Write(digest[:])
	}
	baseDirectory := "."
	if configuration.SourcePath != "" {
		baseDirectory = filepath.Dir(configuration.SourcePath)
	}
	paths := []string{
		resolveConfigurationPath(baseDirectory, configuration.Authentication.GovernedClientsPath),
		resolveConfigurationPath(baseDirectory, configuration.Authentication.ManagedClientsPath),
	}
	for _, directory := range paths {
		if directory == "" {
			continue
		}
		files, err := authenticationFiles(directory)
		if err != nil {
			return sourceManifest{}, err
		}
		hasher.Write([]byte(filepath.Clean(directory)))
		for _, file := range files {
			data, err := readAuthenticationFile(file)
			if err != nil {
				return sourceManifest{}, err
			}
			digest := sha256.Sum256(data)
			hasher.Write([]byte(filepath.Base(file)))
			hasher.Write(digest[:])
		}
	}
	copy(manifest.digest[:], hasher.Sum(nil))
	return manifest, nil
}

func configurationFileDigest(
	path string,
	allowMissing bool,
) ([sha256.Size]byte, bool, error) {
	data, err := readConfigurationFile(path)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return [sha256.Size]byte{}, false, nil
		}
		return [sha256.Size]byte{}, false, fmt.Errorf("read configuration %q: %w", path, err)
	}
	return sha256.Sum256(data), true, nil
}
