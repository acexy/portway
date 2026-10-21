package client

import (
	"context"
	"net"
	"strconv"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

type proxyDialResult struct {
	dataConnection  transport.Stream
	localConnection net.Conn
	transportError  error
	localError      error
	failure         protocol.LinkErrorCode
	cancel          context.CancelFunc
}

// dialProxyConnections joins both dial tasks before returning. Failed attempts
// close every connection they acquired; successful connections belong to the caller.
// The caller must defer result.cancel until the link ends, even on failure.
func (manager *linkManager) dialProxyConnections(
	ctx context.Context,
	proxyType protocol.ProxyType,
	local config.EndpointConfig,
) proxyDialResult {
	type dialResult struct {
		dataConnection  transport.Stream
		localConnection net.Conn
		kind            linkDialKind
		err             error
	}
	results := make(chan dialResult, 2)
	dialContext, cancelDial := context.WithCancel(ctx)
	go func() {
		connection, err := manager.transport.OpenDataStream(dialContext)
		results <- dialResult{dataConnection: connection, kind: linkDialTransport, err: err}
	}()
	go func() {
		localContext, cancelLocal := context.WithTimeout(dialContext, localDialTimeout)
		defer cancelLocal()
		address := net.JoinHostPort(local.IP, strconv.Itoa(int(local.Port)))
		connection, err := (&net.Dialer{}).DialContext(localContext, string(proxyType), address)
		results <- dialResult{localConnection: connection, kind: linkDialLocal, err: err}
	}()
	result := proxyDialResult{cancel: cancelDial}
	for range 2 {
		dial := <-results
		if dial.err != nil {
			if dial.kind == linkDialTransport {
				result.transportError = dial.err
			} else {
				result.localError = dial.err
			}
			cancelDial()
		}
		if dial.dataConnection != nil {
			result.dataConnection = dial.dataConnection
		}
		if dial.localConnection != nil {
			result.localConnection = dial.localConnection
		}
	}
	if result.transportError != nil || result.localError != nil ||
		result.dataConnection == nil || result.localConnection == nil {
		if result.dataConnection != nil {
			result.dataConnection.Close()
		}
		if result.localConnection != nil {
			result.localConnection.Close()
		}
		result.dataConnection = nil
		result.localConnection = nil
		result.failure = classifyLinkDialFailure(ctx, result.transportError, result.localError)
	}
	return result
}
