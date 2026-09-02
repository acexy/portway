package http

import "github.com/acexy/portway/internal/config"

func defaultBenchmarkHTTPConfiguration() config.HTTPConfig {
	return config.DefaultServer().Proxies.HTTP.HTTPConfig
}
