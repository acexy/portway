package ipfilter

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type httpConnectionContextKey struct{}

// HTTPConnectionContext attaches the accepted socket to request contexts.
func HTTPConnectionContext(ctx context.Context, connection net.Conn) context.Context {
	return context.WithValue(ctx, httpConnectionContextKey{}, connection)
}

// HTTPHandler enforces an explicitly trusted client IP chain header. An empty
// header name leaves socket-level listener filtering as the authority.
func HTTPHandler(filter *Filter, headerName string, next http.Handler) http.Handler {
	if !filter.Enabled() || headerName == "" {
		return next
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, ok := request.Context().Value(httpConnectionContextKey{}).(net.Conn)
		if !ok || connection == nil {
			return
		}
		addresses, err := parseHTTPSourceHeader(request.Header.Values(headerName))
		if err != nil {
			filter.logInvalidHTTPHeader(err)
			connection.Close()
			return
		}

		releases := make([]func(), 0, len(addresses))
		for _, address := range addresses {
			release, allowed := filter.RegisterFor(address, "http_header", func() {
				connection.Close()
			})
			if !allowed {
				for _, releaseSource := range releases {
					releaseSource()
				}
				connection.Close()
				return
			}
			releases = append(releases, release)
		}
		defer func() {
			for _, releaseSource := range releases {
				releaseSource()
			}
		}()
		next.ServeHTTP(writer, request)
	})
}

func parseHTTPSourceHeader(values []string) ([]netip.Addr, error) {
	if len(values) == 0 {
		return nil, errors.New("configured client IP header is missing")
	}
	seen := make(map[netip.Addr]struct{})
	addresses := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			source := strings.TrimSpace(part)
			if source == "" {
				return nil, errors.New(
					"configured client IP header contains an empty item",
				)
			}
			address, err := netip.ParseAddr(source)
			if err != nil {
				return nil, errors.New(
					"configured client IP header contains an invalid IP",
				)
			}
			address = address.Unmap()
			if _, exists := seen[address]; exists {
				continue
			}
			seen[address] = struct{}{}
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("configured client IP header contains no IP")
	}
	return addresses, nil
}
