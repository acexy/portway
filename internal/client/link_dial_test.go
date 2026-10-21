package client

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

type proxyDialTestStream struct{ net.Conn }

func (stream proxyDialTestStream) CloseWrite() error { return stream.Close() }

func TestProxyDialKeepsSuccessfulContextUntilLinkEnds(t *testing.T) {
	for _, kind := range []protocol.ProxyType{protocol.ProxyTypeTCP, protocol.ProxyTypeUDP} {
		t.Run(string(kind), func(t *testing.T) {
			var port int
			if kind == protocol.ProxyTypeTCP {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				port = listener.Addr().(*net.TCPAddr).Port
			} else {
				listener, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				port = listener.LocalAddr().(*net.UDPAddr).Port
			}
			connection, peer := net.Pipe()
			defer connection.Close()
			defer peer.Close()
			var dialContext context.Context
			manager := &linkManager{transport: forwardTestSession{open: func(ctx context.Context) (transport.Stream, error) {
				dialContext = ctx
				return proxyDialTestStream{connection}, nil
			}}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := manager.dialProxyConnections(ctx, kind, config.EndpointConfig{IP: "127.0.0.1", Port: uint16(port)})
			defer result.cancel()
			if result.failure != "" {
				t.Fatalf("dial failed: %+v", result)
			}
			defer result.dataConnection.Close()
			defer result.localConnection.Close()
			if dialContext.Err() != nil {
				t.Fatal("successful dial context canceled before link ended")
			}
			if result.localConnection.LocalAddr().Network() != string(kind) {
				t.Fatal("wrong local network")
			}
			result.cancel()
			if dialContext.Err() != context.Canceled {
				t.Fatal("link cancellation did not reach transport")
			}
		})
	}
}

func TestProxyDialClosesLateTransportAfterLocalFailure(t *testing.T) {
	connection, peer := net.Pipe()
	defer connection.Close()
	defer peer.Close()
	manager := &linkManager{transport: forwardTestSession{open: func(ctx context.Context) (transport.Stream, error) {
		<-ctx.Done()
		return proxyDialTestStream{connection}, nil
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	result := manager.dialProxyConnections(ctx, protocol.ProxyTypeTCP, config.EndpointConfig{IP: "[", Port: 1})
	defer result.cancel()
	if result.failure != protocol.LinkErrorLocalDialFailed || result.localError == nil || result.transportError != nil {
		t.Fatalf("unexpected failure classification: %+v", result)
	}
	if result.dataConnection != nil || result.localConnection != nil {
		t.Fatal("failed dial retained connections")
	}
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("late stream not closed: %v", err)
	}
}
