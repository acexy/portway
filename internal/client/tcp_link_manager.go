package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/consts"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	"github.com/acexy/portway/internal/transport"
)

type clientTCPLinkManager struct {
	context       context.Context
	cancel        context.CancelFunc
	logger        *logging.Logger
	configuration config.ClientConfig
	sessionID     string
	writer        *controlWriter
	mutex         sync.Mutex
	links         map[string]context.CancelFunc
	waitGroup     sync.WaitGroup
}

func newClientTCPLinkManager(
	parent context.Context,
	logger *logging.Logger,
	configuration config.ClientConfig,
	sessionID string,
	writer *controlWriter,
) *clientTCPLinkManager {
	ctx, cancel := context.WithCancel(parent)
	return &clientTCPLinkManager{
		context:       ctx,
		cancel:        cancel,
		logger:        logger,
		configuration: configuration,
		sessionID:     sessionID,
		writer:        writer,
		links:         make(map[string]context.CancelFunc),
	}
}

func (manager *clientTCPLinkManager) open(request protocol.OpenLink) {
	manager.mutex.Lock()
	if _, exists := manager.links[request.LinkID]; exists {
		manager.mutex.Unlock()
		return
	}
	linkContext, cancel := context.WithCancel(manager.context)
	manager.links[request.LinkID] = cancel
	manager.waitGroup.Add(1)
	manager.mutex.Unlock()

	go func() {
		defer manager.waitGroup.Done()
		defer manager.remove(request.LinkID)
		manager.run(linkContext, request)
	}()
}

func (manager *clientTCPLinkManager) cancelLink(linkID string) {
	manager.mutex.Lock()
	cancel := manager.links[linkID]
	manager.mutex.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (manager *clientTCPLinkManager) close() {
	manager.cancel()
	manager.mutex.Lock()
	for _, cancel := range manager.links {
		cancel()
	}
	manager.mutex.Unlock()
	manager.waitGroup.Wait()
}

func (manager *clientTCPLinkManager) remove(linkID string) {
	manager.mutex.Lock()
	cancel := manager.links[linkID]
	delete(manager.links, linkID)
	manager.mutex.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (manager *clientTCPLinkManager) run(ctx context.Context, request protocol.OpenLink) {
	logger := manager.logger.WithFields(map[string]any{
		"link_id":    request.LinkID,
		"proxy_name": request.ProxyName,
	})
	proxyConfiguration, exists := manager.findProxy(request.ProxyName)
	if !exists {
		manager.reportFailure(request.LinkID, protocol.LinkErrorLocalDialFailed)
		logger.Error("TCP proxy configuration was not found", errors.New("unknown proxy"))
		return
	}
	if request.ExpiresAtUnixMS <= time.Now().UnixMilli() {
		manager.reportFailure(request.LinkID, protocol.LinkErrorExpired)
		return
	}

	type dialResult struct {
		dataConnection  net.Conn
		localConnection net.Conn
		err             error
	}
	results := make(chan dialResult, 2)
	dialContext, cancelDial := context.WithCancel(ctx)
	defer cancelDial()

	go func() {
		connection, err := transport.DialToken(
			dialContext,
			manager.configuration.ServerAddress,
			manager.configuration.Authentication.Token,
			protocol.RoleData,
		)
		results <- dialResult{dataConnection: connection, err: err}
	}()
	go func() {
		localDialContext, cancelLocalDial := context.WithTimeout(
			dialContext,
			consts.TCPLocalDialTimeout,
		)
		defer cancelLocalDial()
		address := net.JoinHostPort(
			proxyConfiguration.LocalIP,
			fmt.Sprintf("%d", proxyConfiguration.LocalPort),
		)
		connection, err := (&net.Dialer{}).DialContext(localDialContext, "tcp", address)
		results <- dialResult{localConnection: connection, err: err}
	}()

	var dataConnection net.Conn
	var localConnection net.Conn
	var dialError error
	for range 2 {
		result := <-results
		if result.err != nil {
			dialError = errors.Join(dialError, result.err)
			cancelDial()
		}
		if result.dataConnection != nil {
			dataConnection = result.dataConnection
		}
		if result.localConnection != nil {
			localConnection = result.localConnection
		}
	}
	if dialError != nil || dataConnection == nil || localConnection == nil {
		if dataConnection != nil {
			dataConnection.Close()
		}
		if localConnection != nil {
			localConnection.Close()
		}
		manager.reportFailure(request.LinkID, protocol.LinkErrorLocalDialFailed)
		logger.Error("TCP link dial failed", dialError)
		return
	}
	defer dataConnection.Close()
	defer localConnection.Close()

	if err := dataConnection.SetDeadline(time.Now().Add(consts.TCPDataBindTimeout)); err != nil {
		manager.reportFailure(request.LinkID, protocol.LinkErrorTransportFailed)
		return
	}
	if err := protocol.WriteControl(dataConnection, protocol.MessageBindLink, protocol.BindLink{
		ClientID:  manager.configuration.ClientID,
		SessionID: manager.sessionID,
		LinkID:    request.LinkID,
		Ticket:    request.Ticket,
	}); err != nil {
		manager.reportFailure(request.LinkID, protocol.LinkErrorTransportFailed)
		return
	}
	envelope, err := protocol.ReadControl(dataConnection)
	if err != nil {
		manager.reportFailure(request.LinkID, protocol.LinkErrorTransportFailed)
		return
	}
	if envelope.Type != protocol.MessageBindResult {
		manager.reportFailure(request.LinkID, protocol.LinkErrorInvalidBinding)
		return
	}
	var result protocol.BindResult
	if err := protocol.DecodePayload(envelope, &result); err != nil ||
		result.LinkID != request.LinkID ||
		result.Status != protocol.LinkStatusAccepted {
		manager.reportFailure(request.LinkID, protocol.LinkErrorInvalidBinding)
		return
	}
	if err := dataConnection.SetDeadline(time.Time{}); err != nil {
		manager.reportFailure(request.LinkID, protocol.LinkErrorTransportFailed)
		return
	}

	logger.Trace("TCP link streaming started")
	err = proxytcp.Forward(ctx, dataConnection, localConnection)
	if err != nil && ctx.Err() == nil {
		logger.Error("TCP link streaming ended", err)
	} else {
		logger.Trace("TCP link streaming stopped")
	}
}

func (manager *clientTCPLinkManager) findProxy(name string) (config.ProxyConfig, bool) {
	for _, proxyConfiguration := range manager.configuration.Proxies {
		if proxyConfiguration.Name == name &&
			proxyConfiguration.Type == string(protocol.ProxyTypeTCP) {
			return proxyConfiguration, true
		}
	}
	return config.ProxyConfig{}, false
}

func (manager *clientTCPLinkManager) reportFailure(
	linkID string,
	code protocol.LinkErrorCode,
) {
	_ = manager.writer.write(protocol.MessageLinkFailed, protocol.LinkFailed{
		LinkID: linkID,
		Code:   code,
	})
}
