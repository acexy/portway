package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

type recoveryControlStream struct{ net.Conn }

func (s recoveryControlStream) CloseWrite() error { return s.Close() }

type recoveryTransportSession struct {
	transport.ClientSession
	stream transport.Stream
}

func (s recoveryTransportSession) ControlStream() transport.Stream { return s.stream }
func (s recoveryTransportSession) Close() error                    { return s.stream.Close() }

type recoveryTransport struct{ session transport.ClientSession }

func (t recoveryTransport) Connect(context.Context) (transport.ClientSession, error) {
	return t.session, nil
}

func TestManagedInitializationFailureRetainsNewResumeID(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	forwards := []protocol.ManagedForward{{Name: "database", Type: protocol.ForwardTypeTCP, ListenIP: "127.0.0.1", ListenPort: uint16(occupied.Addr().(*net.TCPAddr).Port), TargetIP: "127.0.0.1", TargetPort: 5432}}
	proxies := []protocol.ManagedProxy{}
	digest, err := protocol.ManagedConfigurationDigest(proxies, forwards)
	if err != nil {
		t.Fatal(err)
	}
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	configuration := config.DefaultClient()
	configuration.Authentication.ClientID = "client"
	service := NewService(logging.New("test"), configuration)
	service.transport = recoveryTransport{recoveryTransportSession{stream: recoveryControlStream{clientSide}}}
	service.identification = protocol.ClientIdentification{Product: protocol.ProductClient, Version: "test", OS: protocol.OperatingSystemLinux, Arch: protocol.ArchitectureAMD64, Hostname: "test"}
	serverDone := make(chan error, 1)
	go func() {
		serverSide.SetDeadline(time.Now().Add(5 * time.Second))
		send := func() error {
			if err := protocol.WriteControl(serverSide, protocol.MessageServerIdentification, protocol.ServerIdentification{Product: protocol.ProductServer, Version: "test"}); err != nil {
				return err
			}
			if _, err := protocol.ReadControl(serverSide); err != nil {
				return err
			}
			envelope, err := protocol.ReadControl(serverSide)
			if err != nil {
				return err
			}
			var hello protocol.ClientHello
			if err := protocol.DecodePayload(envelope, &hello); err != nil {
				return err
			}
			if hello.ResumeSessionID != "old-session" {
				return errors.New("missing recovery ID")
			}
			if err := protocol.WriteControl(serverSide, protocol.MessageServerHello, protocol.ServerHello{ClientID: "client", SessionID: "new-session", ManagementMode: protocol.ManagementModeManaged, Resumed: true, Capabilities: hello.Capabilities}); err != nil {
				return err
			}
			if err := protocol.WriteControl(serverSide, protocol.MessageManagedConfigPrepare, protocol.ManagedConfigPrepare{Revision: 1, Digest: digest, Proxies: proxies, Forwards: forwards}); err != nil {
				return err
			}
			envelope, err = protocol.ReadControl(serverSide)
			if err != nil {
				return err
			}
			if envelope.Type != protocol.MessageManagedConfigPrepared {
				return errors.New("client did not prepare")
			}
			return protocol.WriteControl(serverSide, protocol.MessageManagedConfigActivate, protocol.ManagedConfigActivate{Revision: 1, Digest: digest, Forwards: []protocol.ForwardResult{{Name: "database", Type: protocol.ForwardTypeTCP, BindingID: "binding", Active: true}}})
		}
		serverDone <- send()
	}()
	sessionID, established, err := service.runControlSession(ctx, "old-session")
	if err == nil || transport.IsPermanent(err) {
		t.Fatalf("expected retryable runtime failure, got %v", err)
	}
	if sessionID != "new-session" || established {
		t.Fatalf("failed initialization lost recovery identity or reset budget: id=%s established=%v", sessionID, established)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
