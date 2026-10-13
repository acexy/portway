package server

import (
	"fmt"
	"net/http"

	proxyudp "github.com/acexy/portway/internal/proxy/udp"
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
	var forwardUDP proxyudp.Stats
	if s.forwardRegistry != nil {
		forwards := s.forwardRegistry.SnapshotStats()
		forwardUDP = forwards.UDP
		forwardBindings = forwards.Bindings
		activeForwardBindings = forwards.ActiveBindings
		tcpForwards = forwards.TCPBindings
		udpForwards = forwards.UDPBindings
	}
	var tcpProxies, udpProxies, httpProxies int
	var tcpMirrorGroups, udpMirrorGroups, tcpMirrorMembers, udpMirrorMembers int
	var httpRequests, httpUpgrades int
	var udpAssociations, udpPending, udpQueuedBytes int
	if s.proxyRegistry != nil {
		proxies := s.proxyRegistry.SnapshotStats()
		tcpProxies, udpProxies, httpProxies = proxies.TCPProxies, proxies.UDPProxies, proxies.HTTPProxies
		tcpMirrorGroups, udpMirrorGroups = proxies.TCPMirrorGroups, proxies.UDPMirrorGroups
		tcpMirrorMembers, udpMirrorMembers = proxies.TCPMirrorMembers, proxies.UDPMirrorMembers
		httpRequests, httpUpgrades = proxies.HTTPActiveRequests, proxies.HTTPActiveUpgrades
		udpAssociations = proxies.UDP.Associations
		udpPending = proxies.UDP.PendingAssociations
		udpQueuedBytes = proxies.UDP.QueuedBytes
	}

	vnet := s.vnetRuntime.operationsStats()
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
		{"portway_forward_bindings_inactive", "Current non-active Forward bindings; not a failure count.", uint64(forwardBindings - activeForwardBindings)},
		{"portway_forward_udp_associations", "Current server-side Forward UDP associations including pending associations.", uint64(forwardUDP.Associations)},
		{"portway_forward_udp_pending_associations", "Current pending server-side Forward UDP associations.", uint64(forwardUDP.PendingAssociations)},
		{"portway_forward_udp_queued_bytes", "Current queued server-side Forward UDP payload bytes.", uint64(forwardUDP.QueuedBytes)},
		{"portway_tcp_forwards", "Current registered TCP Forwards.", uint64(tcpForwards)},
		{"portway_udp_forwards", "Current registered UDP Forwards.", uint64(udpForwards)},
		{"portway_tcp_proxies", "Current registered TCP proxies.", uint64(tcpProxies)},
		{"portway_udp_proxies", "Current registered UDP proxies.", uint64(udpProxies)},
		{"portway_tcp_mirror_groups", "Current configured TCP mirror groups.", uint64(tcpMirrorGroups)},
		{"portway_udp_mirror_groups", "Current configured UDP mirror groups.", uint64(udpMirrorGroups)},
		{"portway_tcp_mirror_members", "Current registered TCP mirror members.", uint64(tcpMirrorMembers)},
		{"portway_udp_mirror_members", "Current registered UDP mirror members.", uint64(udpMirrorMembers)},
		{"portway_http_proxies", "Current registered HTTP proxies.", uint64(httpProxies)},
		{"portway_http_active_requests", "Current active HTTP requests.", uint64(httpRequests)},
		{"portway_http_active_upgrades", "Current active upgraded HTTP connections.", uint64(httpUpgrades)},
		{"portway_udp_associations", "Current UDP associations including pending associations.", uint64(udpAssociations)},
		{"portway_udp_pending_associations", "Current pending UDP associations.", uint64(udpPending)},
		{"portway_udp_queued_bytes", "Current queued UDP payload bytes.", uint64(udpQueuedBytes)},
		{"portway_vnet_enabled", "Whether server VNet is configured as enabled.", vnet.enabled},
		{"portway_vnet_device_open", "Whether the server runtime holds a VNet device; not an end-to-end health check.", vnet.deviceOpen},
		{"portway_vnet_device_preparing", "Whether server VNet device preparation is in progress.", vnet.preparing},
		{"portway_vnet_nodes", "Current configured VNet nodes.", uint64(vnet.nodes)},
		{"portway_vnet_sessions", "Current attached VNet control sessions; not active node count.", uint64(vnet.sessions)},
		{"portway_vnet_configuration_generation", "Current VNet configuration generation.", vnet.generation},
		{"portway_vnet_pools_pending", "Current pending VNet channel pools.", uint64(vnet.pools.Pending)},
		{"portway_vnet_pools_active", "Current published active VNet channel pools.", uint64(vnet.pools.Active)},
		{"portway_vnet_channels_active", "Current channels in published active VNet pools.", uint64(vnet.pools.ActiveChannels)},
		{"portway_vnet_flows", "Current server router VNet flow records.", uint64(vnet.flows.Active)},
		{"portway_vnet_peer_pairs", "Current server-coordinated VNet peer pairs.", uint64(vnet.peerPairs)},
		{"portway_vnet_direct_pairs", "Current activated VNet direct pairs; not a path health check.", uint64(vnet.directPairs)},
		{"portway_vnet_queued_packets", "Current queued server VNet packets.", uint64(vnet.queues.Queued)},
		{"portway_vnet_userspace_flows", "Current server VNet userspace flow records.", uint64(vnet.userspace.Flows)},
		{"portway_vnet_tcp_connections", "Current server VNet userspace TCP connections.", uint64(vnet.userspace.TCPConnections)},
		{"portway_vnet_udp_associations", "Current server VNet userspace UDP associations.", uint64(vnet.userspace.UDPAssociations)},
	}
	for _, metric := range metrics {
		_, _ = fmt.Fprintf(response, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", metric.name, metric.help, metric.name, metric.name, metric.value)
	}
	counters := []struct {
		name  string
		help  string
		value uint64
	}{
		{"portway_vnet_capacity_rejected_total", "VNet router capacity rejections in this server runtime.", vnet.flows.CapacityRejected},
		{"portway_vnet_rate_rejected_total", "VNet router rate rejections in this server runtime.", vnet.flows.RateRejected},
		{"portway_vnet_policy_rejected_total", "VNet router policy rejections in this server runtime.", vnet.flows.PolicyRejected},
		{"portway_vnet_queue_rejected_total", "VNet packet queue admission rejections in this server runtime.", vnet.queues.Rejected},
		{"portway_vnet_queue_expired_total", "VNet queued packet expirations in this server runtime.", vnet.queues.Expired},
		{"portway_vnet_queue_revoked_total", "VNet queued packet authorization revocations in this server runtime.", vnet.queues.Revoked},
		{"portway_vnet_queue_write_failed_total", "VNet queued packet write failures in this server runtime.", vnet.queues.WriteFailed},
	}
	for _, metric := range counters {
		_, _ = fmt.Fprintf(response, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", metric.name, metric.help, metric.name, metric.name, metric.value)
	}
}
