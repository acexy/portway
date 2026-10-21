package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	proxyudp "github.com/acexy/portway/internal/proxy/udp"
	"github.com/acexy/portway/internal/transport"
)

type linkManager struct {
	context     context.Context
	cancel      context.CancelFunc
	logger      *logging.Logger
	clientID    string
	proxies     map[string]config.ProxyConfig
	sessionID   string
	writer      *control.Writer
	transport   transport.ClientSession
	mutex       sync.Mutex
	links       map[string]context.CancelFunc
	waitGroup   sync.WaitGroup
	failureLogs *logging.WindowCounter
}

func newLinkManager(
	parent context.Context,
	logger *logging.Logger,
	clientID string,
	proxies []config.ProxyConfig,
	sessionID string,
	writer *control.Writer,
	transportSession transport.ClientSession,
) *linkManager {
	ctx, cancel := context.WithCancel(parent)
	return &linkManager{
		context:     ctx,
		cancel:      cancel,
		logger:      logger,
		clientID:    clientID,
		proxies:     indexProxyConfigurations(proxies),
		sessionID:   sessionID,
		writer:      writer,
		transport:   transportSession,
		links:       make(map[string]context.CancelFunc),
		failureLogs: logging.NewWindowCounter(time.Minute),
	}
}

func (manager *linkManager) open(request protocol.OpenLink) {
	manager.mutex.Lock()
	if _, exists := manager.links[request.LinkID]; exists {
		manager.mutex.Unlock()
		return
	}
	linkContext, cancel := context.WithCancel(manager.context)
	manager.links[request.LinkID] = cancel
	manager.waitGroup.Go(func() {
		defer manager.remove(request.LinkID)
		manager.run(linkContext, request)
	})
	manager.mutex.Unlock()
}

func (manager *linkManager) cancelLink(linkID string) {
	manager.mutex.Lock()
	cancel := manager.links[linkID]
	manager.mutex.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (manager *linkManager) close() {
	manager.cancel()
	manager.mutex.Lock()
	for _, cancel := range manager.links {
		cancel()
	}
	manager.mutex.Unlock()
	manager.waitGroup.Wait()
}

func (manager *linkManager) remove(linkID string) {
	manager.mutex.Lock()
	cancel := manager.links[linkID]
	delete(manager.links, linkID)
	manager.mutex.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (manager *linkManager) run(ctx context.Context, request protocol.OpenLink) {
	startedAt := time.Now()
	logger := manager.logger.WithFields(map[string]any{
		"link_id":    request.LinkID,
		"proxy_name": request.ProxyName,
		"proxy_type": request.ProxyType,
	})
	proxyConfiguration, exists := manager.findProxy(request.ProxyName, request.ProxyType)
	if !exists {
		manager.reportFailure(request.LinkID, protocol.LinkErrorLocalDialFailed)
		logger.Error("proxy configuration was not found", errors.New("unknown proxy"))
		return
	}
	if request.ExpiresAtUnixMS <= time.Now().UnixMilli() {
		manager.reportFailure(request.LinkID, protocol.LinkErrorExpired)
		logger.DebugWithFields("proxy link expired", map[string]any{
			"event":       "proxy_link_failed",
			"result":      "failed",
			"reason":      "link_expired",
			"error_code":  protocol.LinkErrorExpired,
			"duration_ms": time.Since(startedAt).Milliseconds(),
		})
		return
	}
	if request.ProxyType == protocol.ProxyTypeUDP {
		manager.runUDP(ctx, logger, request, proxyConfiguration)
		return
	}

	dialResult := manager.dialProxyConnections(ctx, protocol.ProxyTypeTCP, proxyConfiguration.Local)
	defer dialResult.cancel()
	if dialResult.failure != "" {
		failureCode := dialResult.failure
		manager.reportFailure(request.LinkID, failureCode)
		manager.warnLinkFailureSummary()
		logger.DebugWithFields(
			"proxy link dial failed",
			map[string]any{
				"event":       "proxy_link_failed",
				"result":      "failed",
				"reason":      "dial_failed",
				"error_code":  failureCode,
				"duration_ms": time.Since(startedAt).Milliseconds(),
				"error":       errors.Join(dialResult.transportError, dialResult.localError),
			},
		)
		return
	}
	dataConnection, localConnection := dialResult.dataConnection, dialResult.localConnection
	defer dataConnection.Close()
	defer localConnection.Close()

	if failure := manager.bindDataStream(dataConnection, request); failure != "" {
		manager.reportFailure(request.LinkID, failure)
		manager.warnLinkFailureSummary()
		logger.DebugWithFields("proxy link bind failed", map[string]any{
			"event":       "proxy_link_failed",
			"result":      "failed",
			"reason":      "bind_failed",
			"error_code":  failure,
			"duration_ms": time.Since(startedAt).Milliseconds(),
		})
		return
	}

	setupDuration := time.Since(startedAt)
	logger.TraceWithFields("proxy link streaming started", map[string]any{
		"event": "proxy_link_started",
	})
	forwardResult, err := proxytcp.Forward(ctx, dataConnection, localConnection)
	fields := map[string]any{
		"event":                    "proxy_link_closed",
		"transport_to_local_bytes": forwardResult.LeftToRightBytes,
		"local_to_transport_bytes": forwardResult.RightToLeftBytes,
		"duration_ms":              time.Since(startedAt).Milliseconds(),
		"setup_ms":                 setupDuration.Milliseconds(),
	}
	if err != nil && ctx.Err() == nil {
		fields["result"] = "failed"
		fields["reason"] = proxytcp.CloseReason(ctx, err)
		fields["error_code"] = fields["reason"]
		fields["error"] = err
		logger.DebugWithFields("proxy link closed", fields)
	} else {
		fields["result"] = "completed"
		if ctx.Err() != nil {
			fields["result"] = "cancelled"
			fields["reason"] = "link_cancelled"
		}
		logger.DebugWithFields("proxy link closed", fields)
	}
}

func (manager *linkManager) warnLinkFailureSummary() {
	count, emit := manager.failureLogs.Record(time.Now())
	if !emit {
		return
	}
	manager.logger.WarnWithFields(
		"proxy link failed; additional failures are rate limited",
		nil,
		map[string]any{
			"event":         "proxy_link_failure_summary",
			"scope":         "proxy_links",
			"failure_count": count,
		},
	)
}

func (manager *linkManager) bindDataStream(
	dataConnection transport.Stream,
	request protocol.OpenLink,
) protocol.LinkErrorCode {
	if err := dataConnection.SetDeadline(time.Now().Add(dataBindTimeout)); err != nil {
		return protocol.LinkErrorTransportFailed
	}
	if err := protocol.WriteControl(dataConnection, protocol.MessageBindLink, protocol.BindLink{
		ClientID:  manager.clientID,
		SessionID: manager.sessionID,
		LinkID:    request.LinkID,
		ProxyType: request.ProxyType,
		BindingID: request.BindingID,
		Ticket:    request.Ticket,
	}); err != nil {
		return protocol.LinkErrorTransportFailed
	}
	envelope, err := protocol.ReadControl(dataConnection)
	if err != nil {
		return protocol.LinkErrorTransportFailed
	}
	if envelope.Type != protocol.MessageBindResult {
		return protocol.LinkErrorInvalidBinding
	}
	return completeLinkBinding(dataConnection, envelope, request.LinkID)
}

func (manager *linkManager) runUDP(
	ctx context.Context,
	logger *logging.Logger,
	request protocol.OpenLink,
	proxyConfiguration config.ProxyConfig,
) {
	if request.MaxDatagramSize == 0 || request.MaxDatagramSize > 65507 ||
		request.WriteTimeoutMS < 100 || request.WriteTimeoutMS > 30000 {
		manager.reportFailure(request.LinkID, protocol.LinkErrorInvalidBinding)
		return
	}
	dialResult := manager.dialProxyConnections(ctx, protocol.ProxyTypeUDP, proxyConfiguration.Local)
	defer dialResult.cancel()
	if dialResult.failure != "" {
		manager.reportFailure(request.LinkID, dialResult.failure)
		return
	}
	dataConnection, localConnection := dialResult.dataConnection, dialResult.localConnection
	defer dataConnection.Close()
	defer localConnection.Close()
	if failure := manager.bindDataStream(dataConnection, request); failure != "" {
		manager.reportFailure(request.LinkID, failure)
		return
	}
	logger.Trace("UDP proxy association streaming started")
	err := proxyudp.Forward(
		ctx,
		dataConnection,
		localConnection,
		int(request.MaxDatagramSize),
		time.Duration(request.WriteTimeoutMS)*time.Millisecond,
	)
	if err != nil && ctx.Err() == nil &&
		!errors.Is(err, net.ErrClosed) &&
		!errors.Is(err, io.EOF) {
		logger.Error("UDP proxy association streaming ended", err)
	} else {
		logger.Trace("UDP proxy association streaming stopped")
	}
}

type linkDialKind uint8

const (
	linkDialTransport linkDialKind = iota + 1
	linkDialLocal
)

func classifyLinkDialFailure(
	ctx context.Context,
	transportError error,
	localError error,
) protocol.LinkErrorCode {
	if ctx.Err() != nil {
		return protocol.LinkErrorCancelled
	}
	if localError != nil && !errors.Is(localError, context.Canceled) {
		return protocol.LinkErrorLocalDialFailed
	}
	if transportError != nil && !errors.Is(transportError, context.Canceled) {
		return protocol.LinkErrorTransportFailed
	}
	if localError != nil {
		return protocol.LinkErrorLocalDialFailed
	}
	return protocol.LinkErrorTransportFailed
}

func (manager *linkManager) findProxy(
	name string,
	proxyType protocol.ProxyType,
) (config.ProxyConfig, bool) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	proxyConfiguration, exists := manager.proxies[name]
	return proxyConfiguration, exists &&
		proxyConfiguration.Type == proxyType
}

func (manager *linkManager) updateProxies(proxies []config.ProxyConfig) {
	manager.mutex.Lock()
	manager.proxies = indexProxyConfigurations(proxies)
	manager.mutex.Unlock()
}

func indexProxyConfigurations(proxies []config.ProxyConfig) map[string]config.ProxyConfig {
	indexed := coll.SliceGroupBySingle(proxies, func(proxyConfiguration config.ProxyConfig) string {
		return proxyConfiguration.Name
	})
	if indexed == nil {
		return map[string]config.ProxyConfig{}
	}
	return indexed
}

func (manager *linkManager) reportFailure(
	linkID string,
	code protocol.LinkErrorCode,
) {
	_ = manager.writer.Write(protocol.MessageLinkFailed, protocol.LinkFailed{
		LinkID: linkID,
		Code:   code,
	})
}
