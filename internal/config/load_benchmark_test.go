package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkLoadServerUnchangedSources(b *testing.B) {
	for _, clientCount := range []int{0, 128, 1024} {
		b.Run(fmt.Sprintf("governed_%d", clientCount), func(b *testing.B) {
			directory := b.TempDir()
			governedDirectory := filepath.Join(directory, "governed")
			if err := os.Mkdir(governedDirectory, 0o700); err != nil {
				b.Fatal(err)
			}
			serverPath := filepath.Join(directory, "server.yaml")
			serverConfiguration := "authentication:\n  shared_token: benchmark-shared-token-with-more-than-32-characters\n  governed_clients_path: governed\n"
			if err := os.WriteFile(serverPath, []byte(serverConfiguration), 0o600); err != nil {
				b.Fatal(err)
			}
			for index := range clientCount {
				clientConfiguration := fmt.Sprintf("authentication:\n  client_id: benchmark-%d\n  token: benchmark-governed-token-with-more-than-32-characters-%d\npermissions:\n  proxies:\n    tcp:\n      port_ranges:\n        - start: 20000\n          end: 20999\n", index, index)
				path := filepath.Join(governedDirectory, fmt.Sprintf("client-%04d.yaml", index))
				if err := os.WriteFile(path, []byte(clientConfiguration), 0o600); err != nil {
					b.Fatal(err)
				}
			}
			configuration, err := LoadServer(serverPath, false)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("full_load", func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					if _, err := LoadServer(serverPath, false); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("unchanged_check", func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					unchanged, err := ServerSourcesUnchanged(configuration)
					if err != nil || !unchanged {
						b.Fatalf("stable source check failed: unchanged=%t, err=%v", unchanged, err)
					}
				}
			})
		})
	}
}
