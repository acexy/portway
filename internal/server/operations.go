package server

import (
	"fmt"
	"net/http"
)

func (s *Service) operationsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !s.ready.Load() {
			response.WriteHeader(http.StatusServiceUnavailable)
			_, _ = response.Write([]byte("not ready\n"))
			return
		}
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("ready\n"))
	})
	mux.HandleFunc("GET /metrics", s.writeMetrics)
	return mux
}

func (s *Service) writeMetrics(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	ready := 0
	if s.ready.Load() {
		ready = 1
	}
	sessions := s.clientRegistry.SnapshotStats()
	linksPending, linksActive, forwardLinksPending, forwardLinksActive := 0, 0, 0, 0
	if s.linkBroker != nil {
		links := s.linkBroker.SnapshotStats()
		linksPending, linksActive = links.Pending, links.Active
		forwardLinksPending, forwardLinksActive = links.ForwardPending, links.ForwardActive
	}
	var forwardBindings, activeForwardBindings, tcpForwards, udpForwards int
	if s.forwardRegistry != nil {
		forwards := s.forwardRegistry.SnapshotStats()
		forwardBindings = forwards.Bindings
		activeForwardBindings = forwards.ActiveBindings
		tcpForwards = forwards.TCPBindings
		udpForwards = forwards.UDPBindings
	}
	var tcpProxies, udpProxies, httpProxies int
	var httpRequests, httpUpgrades int
	var udpAssociations, udpPending, udpQueuedBytes int
	if s.proxyRegistry != nil {
		proxies := s.proxyRegistry.SnapshotStats()
		tcpProxies, udpProxies, httpProxies = proxies.TCPProxies, proxies.UDPProxies, proxies.HTTPProxies
		httpRequests, httpUpgrades = proxies.HTTPActiveRequests, proxies.HTTPActiveUpgrades
		udpAssociations = proxies.UDP.Associations
		udpPending = proxies.UDP.PendingAssociations
		udpQueuedBytes = proxies.UDP.QueuedBytes
	}

	metrics := []struct {
		name  string
		help  string
		value uint64
	}{
		{"portway_ready", "Whether portwayd has initialized all configured listeners.", uint64(ready)},
		{"portway_configuration_generation", "Current published server configuration generation.", s.currentConfigurationGeneration()},
		{"portway_sessions_initializing", "Current initializing control sessions.", uint64(sessions.Initializing)},
		{"portway_sessions_active", "Current active control sessions.", uint64(sessions.Active)},
		{"portway_sessions_suspended", "Current suspended control sessions.", uint64(sessions.Suspended)},
		{"portway_links_pending", "Current pending data links.", uint64(linksPending)},
		{"portway_links_active", "Current active data links.", uint64(linksActive)},
		{"portway_forward_links_pending", "Current pending Forward data links.", uint64(forwardLinksPending)},
		{"portway_forward_links_active", "Current active Forward data links.", uint64(forwardLinksActive)},
		{"portway_forward_bindings", "Current registered Forward bindings.", uint64(forwardBindings)},
		{"portway_forward_bindings_active", "Current active Forward bindings.", uint64(activeForwardBindings)},
		{"portway_tcp_forwards", "Current registered TCP Forwards.", uint64(tcpForwards)},
		{"portway_udp_forwards", "Current registered UDP Forwards.", uint64(udpForwards)},
		{"portway_tcp_proxies", "Current registered TCP proxies.", uint64(tcpProxies)},
		{"portway_udp_proxies", "Current registered UDP proxies.", uint64(udpProxies)},
		{"portway_http_proxies", "Current registered HTTP proxies.", uint64(httpProxies)},
		{"portway_http_active_requests", "Current active HTTP requests.", uint64(httpRequests)},
		{"portway_http_active_upgrades", "Current active upgraded HTTP connections.", uint64(httpUpgrades)},
		{"portway_udp_associations", "Current UDP associations including pending associations.", uint64(udpAssociations)},
		{"portway_udp_pending_associations", "Current pending UDP associations.", uint64(udpPending)},
		{"portway_udp_queued_bytes", "Current queued UDP payload bytes.", uint64(udpQueuedBytes)},
	}
	for _, metric := range metrics {
		_, _ = fmt.Fprintf(response, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", metric.name, metric.help, metric.name, metric.name, metric.value)
	}
}
