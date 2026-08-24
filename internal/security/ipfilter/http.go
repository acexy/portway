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
type httpSourceAddressesContextKey struct{}

// HTTPConnectionContext attaches the accepted socket to request contexts.
func HTTPConnectionContext(ctx context.Context, connection net.Conn) context.Context {
	return context.WithValue(ctx, httpConnectionContextKey{}, connection)
}

// HTTPHandler enforces an explicitly trusted client IP chain header for HTTP
// or TLS-terminated HTTPS. An empty header name leaves socket filtering as the
// authority. The optional ingress labels deny events by public listener.
func HTTPHandler(
	filter *Filter,
	headerName string,
	next http.Handler,
	ingresses ...string,
) http.Handler {
	if !filter.Enabled() || headerName == "" {
		return next
	}
	ingress := "http_header"
	if len(ingresses) > 0 && ingresses[0] != "" {
		ingress = ingresses[0]
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
			release, allowed := filter.RegisterFor(address, ingress, func() {
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
		request = request.WithContext(context.WithValue(
			request.Context(),
			httpSourceAddressesContextKey{},
			addresses,
		))
		next.ServeHTTP(writer, request)
	})
}

// HTTPSourceAddresses returns the normalized client IP chain validated by
// HTTPHandler. The returned slice is a copy and is safe for the caller to retain.
func HTTPSourceAddresses(request *http.Request) []netip.Addr {
	if request == nil {
		return nil
	}
	addresses, _ := request.Context().Value(httpSourceAddressesContextKey{}).([]netip.Addr)
	return append([]netip.Addr(nil), addresses...)
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
