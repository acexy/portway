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
	sessionID, established, stable, err := service.runControlSession(ctx, "old-session", time.Time{})
	if err == nil || transport.IsPermanent(err) {
		t.Fatalf("expected retryable runtime failure, got %v", err)
	}
	if sessionID != "new-session" || established || stable {
		t.Fatalf("failed initialization lost recovery identity or reset budget: id=%s established=%v", sessionID, established)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestDeclaredInitializationFailureRetainsResumeIdentity(t *testing.T) {
	for _, mode := range []protocol.ManagementMode{protocol.ManagementModeShared, protocol.ManagementModeGoverned} {
		for _, resumed := range []bool{false, true} {
			name := string(mode) + "/fresh"
			if resumed {
				name = string(mode) + "/resumed"
			}
			t.Run(name, func(t *testing.T) {
				local, peer := net.Pipe()
				defer local.Close()
				defer peer.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				configuration := config.DefaultClient()
				configuration.Authentication.ClientID = "client"
				configuration.Proxies = []config.ProxyConfig{{Name: "database", Type: protocol.ProxyTypeTCP, Local: config.EndpointConfig{IP: "127.0.0.1", Port: 5432}, Public: config.ProxyPublicConfig{Port: 15432}}}
				service := NewService(logging.New("test"), configuration)
				service.transport = recoveryTransport{recoveryTransportSession{stream: recoveryControlStream{local}}}
				service.identification = protocol.ClientIdentification{Product: protocol.ProductClient, Version: "test", OS: protocol.OperatingSystemLinux, Arch: protocol.ArchitectureAMD64, Hostname: "test"}
				serverDone := make(chan error, 1)
				go func() {
					defer peer.Close()
					peer.SetDeadline(time.Now().Add(3 * time.Second))
					if err := protocol.WriteControl(peer, protocol.MessageServerIdentification, protocol.ServerIdentification{Product: protocol.ProductServer, Version: "test"}); err != nil {
						serverDone <- err
						return
					}
					if _, err := protocol.ReadControl(peer); err != nil {
						serverDone <- err
						return
					}
					envelope, err := protocol.ReadControl(peer)
					if err != nil {
						serverDone <- err
						return
					}
					var hello protocol.ClientHello
					if err := protocol.DecodePayload(envelope, &hello); err != nil {
						serverDone <- err
						return
					}
					if err := protocol.WriteControl(peer, protocol.MessageServerHello, protocol.ServerHello{ClientID: "client", SessionID: "new-session", ManagementMode: mode, Resumed: resumed, Capabilities: hello.Capabilities}); err != nil {
						serverDone <- err
						return
					}
					envelope, err = protocol.ReadControl(peer)
					if err == nil && envelope.Type != protocol.MessageSyncConfiguration {
						err = errors.New("expected configuration synchronization")
					}
					serverDone <- err
				}()
				resumeID := ""
				expectedID := ""
				if resumed {
					resumeID, expectedID = "old-session", "new-session"
				}
				id, established, stable, err := service.runControlSession(ctx, resumeID, time.Time{})
				if err == nil || transport.IsPermanent(err) || established || stable || id != expectedID {
					t.Fatalf("unexpected failed initialization: id=%q established=%v stable=%v err=%v", id, established, stable, err)
				}
				if err := <-serverDone; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

type deadlineTransport struct{ deadline time.Time }

func (transport deadlineTransport) Connect(ctx context.Context) (transportSession transport.ClientSession, err error) {
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.Equal(transport.deadline) {
		return nil, errors.New("setup did not preserve earlier deadline")
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestControlSetupHonorsRecoveryAndParentDeadlines(t *testing.T) {
	for _, parentDeadline := range []bool{false, true} {
		name := "recovery"
		if parentDeadline {
			name = "parent"
		}
		t.Run(name, func(t *testing.T) {
			deadline := time.Now().Add(30 * time.Millisecond)
			ctx := context.Background()
			recoveryDeadline := deadline
			if parentDeadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, deadline)
				defer cancel()
				recoveryDeadline = time.Time{}
			}
			service := NewService(logging.New("test"), config.DefaultClient())
			service.transport = deadlineTransport{deadline}
			_, established, stable, err := service.runControlSession(ctx, "", recoveryDeadline)
			if !errors.Is(err, context.DeadlineExceeded) || established || stable {
				t.Fatalf("unexpected setup result: %v", err)
			}
		})
	}
}
