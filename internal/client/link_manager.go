package client

import (
	"context"
	"errors"
	"fmt"
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
	if request.ProxyType == protocol.ProxyTypeUDP {
		manager.runUDP(ctx, logger, request, proxyConfiguration)
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

	if failure := manager.bindDataStream(dataConnection, request); failure != "" {
		manager.reportFailure(request.LinkID, failure)
		return
	}

	logger.Trace("proxy link streaming started")
	err := proxytcp.Forward(ctx, dataConnection, localConnection)
	if err != nil && ctx.Err() == nil {
		logger.Error("proxy link streaming ended", err)
	} else {
		logger.Trace("proxy link streaming stopped")
	}
}

func (manager *linkManager) bindDataStream(
	dataConnection transport.Stream,
	request protocol.OpenLink,
) protocol.LinkErrorCode {
	if err := dataConnection.SetDeadline(time.Now().Add(dataBindTimeout)); err != nil {
		return protocol.LinkErrorTransportFailed
	}
	if err := protocol.WriteControl(dataConnection, protocol.MessageBindLink, protocol.BindLink{
		ClientID: manager.configuration.ClientID,
		SessionID: manager.sessionID,
		LinkID: request.LinkID,
		ProxyType: request.ProxyType,
		BindingID: request.BindingID,
		Ticket: request.Ticket,
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
	var result protocol.BindResult
	if err := protocol.DecodePayload(envelope, &result); err != nil ||
		result.LinkID != request.LinkID {
		return protocol.LinkErrorInvalidBinding
	}
	if result.Status != protocol.LinkStatusAccepted {
		if result.Error != nil {
			return *result.Error
		}
		return protocol.LinkErrorInvalidBinding
	}
	if err := dataConnection.SetDeadline(time.Time{}); err != nil {
		return protocol.LinkErrorTransportFailed
	}
	return ""
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
	address := net.JoinHostPort(
		proxyConfiguration.LocalIP,
		fmt.Sprintf("%d", proxyConfiguration.LocalPort),
	)
	type udpDialResult struct {
		dataConnection transport.Stream
		localConnection net.Conn
		kind linkDialKind
		err error
	}
	results := make(chan udpDialResult, 2)
	dialContext, cancelDial := context.WithCancel(ctx)
	defer cancelDial()
	go func() {
		connection, err := manager.transport.OpenDataStream(dialContext)
		results <- udpDialResult{
			dataConnection: connection,
			kind: linkDialTransport,
			err: err,
		}
	}()
	go func() {
		localContext, cancelLocal := context.WithTimeout(
			dialContext,
			localDialTimeout,
		)
		defer cancelLocal()
		connection, err := (&net.Dialer{}).DialContext(
			localContext,
			"udp",
			address,
		)
		results <- udpDialResult{
			localConnection: connection,
			kind: linkDialLocal,
			err: err,
		}
	}()
	var dataConnection transport.Stream
	var localConnection net.Conn
	var transportError error
	var localError error
	for range 2 {
		result := <-results
		if result.err != nil {
			cancelDial()
			if result.kind == linkDialTransport {
				transportError = result.err
			} else {
				localError = result.err
			}
		}
		if result.dataConnection != nil {
			dataConnection = result.dataConnection
		}
		if result.localConnection != nil {
			localConnection = result.localConnection
		}
	}
	if transportError != nil || localError != nil ||
		dataConnection == nil || localConnection == nil {
		if dataConnection != nil {
			dataConnection.Close()
		}
		if localConnection != nil {
			localConnection.Close()
		}
		manager.reportFailure(
			request.LinkID,
			classifyLinkDialFailure(ctx, transportError, localError),
		)
		return
	}
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
	return coll.SliceFind(
		manager.configuration.Proxies,
		func(proxyConfiguration config.ProxyConfig) bool {
			return proxyConfiguration.Name == name &&
				proxyConfiguration.Type == string(proxyType)
		},
	)
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
