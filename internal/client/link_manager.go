package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/control"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	"github.com/acexy/portway/internal/transport"
)

type linkManager struct {
	context       context.Context
	cancel        context.CancelFunc
	logger        *logging.Logger
	configuration config.ClientConfig
	sessionID     string
	writer        *control.Writer
	transport     transport.ClientSession
	mutex         sync.Mutex
	links         map[string]context.CancelFunc
	waitGroup     sync.WaitGroup
}

func newLinkManager(
	parent context.Context,
	logger *logging.Logger,
	configuration config.ClientConfig,
	sessionID string,
	writer *control.Writer,
	transportSession transport.ClientSession,
) *linkManager {
	ctx, cancel := context.WithCancel(parent)
	return &linkManager{
		context:       ctx,
		cancel:        cancel,
		logger:        logger,
		configuration: configuration,
		sessionID:     sessionID,
		writer:        writer,
		transport:     transportSession,
		links:         make(map[string]context.CancelFunc),
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
	manager.waitGroup.Add(1)
	manager.mutex.Unlock()

	go func() {
		defer manager.waitGroup.Done()
		defer manager.remove(request.LinkID)
		manager.run(linkContext, request)
	}()
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
	logger := manager.logger.WithFields(map[string]any{
		"link_id":    request.LinkID,
		"proxy_name": request.ProxyName,
	})
	proxyConfiguration, exists := manager.findProxy(request.ProxyName, request.ProxyType)
	if !exists {
		manager.reportFailure(request.LinkID, protocol.LinkErrorLocalDialFailed)
		logger.Error("proxy configuration was not found", errors.New("unknown proxy"))
		return
	}
	if request.ExpiresAtUnixMS <= time.Now().UnixMilli() {
		manager.reportFailure(request.LinkID, protocol.LinkErrorExpired)
		return
	}

	type dialResult struct {
		dataConnection  transport.Stream
		localConnection net.Conn
		kind            linkDialKind
		err             error
	}
	results := make(chan dialResult, 2)
	dialContext, cancelDial := context.WithCancel(ctx)
	defer cancelDial()

	go func() {
		connection, err := manager.transport.OpenDataStream(dialContext)
		results <- dialResult{
			dataConnection: connection,
			kind:           linkDialTransport,
			err:            err,
		}
	}()
	go func() {
		localDialContext, cancelLocalDial := context.WithTimeout(
			dialContext,
			localDialTimeout,
		)
		defer cancelLocalDial()
		address := net.JoinHostPort(
			proxyConfiguration.LocalIP,
			fmt.Sprintf("%d", proxyConfiguration.LocalPort),
		)
		connection, err := (&net.Dialer{}).DialContext(localDialContext, "tcp", address)
		results <- dialResult{
			localConnection: connection,
			kind:            linkDialLocal,
			err:             err,
		}
	}()

	var dataConnection transport.Stream
	var localConnection net.Conn
	var transportDialError error
	var localDialError error
	for range 2 {
		result := <-results
		if result.err != nil {
			if result.kind == linkDialTransport {
				transportDialError = result.err
			} else {
				localDialError = result.err
			}
			cancelDial()
		}
		if result.dataConnection != nil {
			dataConnection = result.dataConnection
		}
		if result.localConnection != nil {
			localConnection = result.localConnection
		}
	}
	if transportDialError != nil || localDialError != nil ||
		dataConnection == nil || localConnection == nil {
		if dataConnection != nil {
			dataConnection.Close()
		}
		if localConnection != nil {
			localConnection.Close()
		}
		failureCode := classifyLinkDialFailure(ctx, transportDialError, localDialError)
		manager.reportFailure(request.LinkID, failureCode)
		logger.Error(
			"proxy link dial failed",
			errors.Join(transportDialError, localDialError),
		)
		return
	}
	defer dataConnection.Close()
	defer localConnection.Close()

	if err := dataConnection.SetDeadline(time.Now().Add(dataBindTimeout)); err != nil {
		manager.reportFailure(request.LinkID, protocol.LinkErrorTransportFailed)
		return
	}
	if err := protocol.WriteControl(dataConnection, protocol.MessageBindLink, protocol.BindLink{
		ClientID:  manager.configuration.ClientID,
		SessionID: manager.sessionID,
		LinkID:    request.LinkID,
		ProxyType: request.ProxyType,
		BindingID: request.BindingID,
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
		result.LinkID != request.LinkID {
		manager.reportFailure(request.LinkID, protocol.LinkErrorInvalidBinding)
		return
	}
	if result.Status != protocol.LinkStatusAccepted {
		failureCode := protocol.LinkErrorInvalidBinding
		if result.Error != nil {
			failureCode = *result.Error
		}
		manager.reportFailure(request.LinkID, failureCode)
		return
	}
	if err := dataConnection.SetDeadline(time.Time{}); err != nil {
		manager.reportFailure(request.LinkID, protocol.LinkErrorTransportFailed)
		return
	}

	logger.Trace("proxy link streaming started")
	err = proxytcp.Forward(ctx, dataConnection, localConnection)
	if err != nil && ctx.Err() == nil {
		logger.Error("proxy link streaming ended", err)
	} else {
		logger.Trace("proxy link streaming stopped")
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
	for _, proxyConfiguration := range manager.configuration.Proxies {
		if proxyConfiguration.Name == name &&
			proxyConfiguration.Type == string(proxyType) {
			return proxyConfiguration, true
		}
	}
	return config.ProxyConfig{}, false
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
