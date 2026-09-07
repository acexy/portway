package server

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport"
)

func startMirrorRecoveryServer(
	t *testing.T,
	proxyType protocol.ProxyType,
	transportType transport.Type,
	localPorts [2]uint16,
) (*Service, string) {
	t.Helper()
	serverConfiguration := config.DefaultServer()
	clientConfiguration := config.DefaultClient()
	serverAddress := reserveTCPAddress(t).String()
	if transportType == transport.TypeQUIC {
		serverAddress = reserveUDPAddress(t).String()
		certificateFile, keyFile := writeQUICServerCertificate(t)
		serverConfiguration.Transport.Type = transportType
		serverConfiguration.Transport.QUIC.CertFile = certificateFile
		serverConfiguration.Transport.QUIC.KeyFile = keyFile
		clientConfiguration.Transport.Type = transportType
		clientConfiguration.Transport.QUIC.ServerName = "localhost"
		clientConfiguration.Transport.QUIC.CAFile = certificateFile
	}
	proxyAddress := reserveTCPAddress(t).String()
	proxyPort := uint16(0)
	if proxyType == protocol.ProxyTypeUDP {
		address := reserveUDPAddress(t)
		proxyAddress, proxyPort = address.String(), uint16(address.Port)
	} else {
		address, err := net.ResolveTCPAddr("tcp", proxyAddress)
		if err != nil {
			t.Fatal(err)
		}
		proxyPort = uint16(address.Port)
	}
	serverConfiguration.Transport.ListenAddress = serverAddress
	serverConfiguration.Proxies.BindIP = "127.0.0.1"
	serverConfiguration.Authentication.SharedToken = nil
	serverConfiguration.GovernedClients = make(map[string]config.GovernedClientConfig)
	clientIDs := []string{"recovery-primary", "recovery-mirror"}
	for _, clientID := range clientIDs {
		permission := &config.ProxyPermission{PortRanges: []config.PortRange{{Start: proxyPort, End: proxyPort}}}
		permissions := config.GovernedProxyPermissions{Limits: config.DefaultProxyPermissionLimits()}
		if proxyType == protocol.ProxyTypeTCP {
			permissions.TCP = permission
		} else {
			permissions.UDP = permission
		}
		serverConfiguration.GovernedClients[clientID] = config.GovernedClientConfig{
			Authentication: config.ClientAuthenticationConfig{
				ClientID: clientID, Token: clientID + "-test-token-at-least-32-bytes-long",
			},
			Permissions: config.GovernedPermissions{Proxies: permissions},
		}
	}
	serverConfiguration.Proxies.Mirror.Governed = []config.ProxyMirrorGroupConfig{{
		Name: "recovery", Type: proxyType, Public: mirrorPublicConfig(proxyPort),
		PrimaryClientID: clientIDs[0], ClientIDs: clientIDs,
	}}
	ctx, cancel := context.WithCancel(context.Background())
	server := NewService(logging.New("test-mirror-recovery"), serverConfiguration)
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Run(ctx) }()
	clientErrors := make([]chan error, len(clientIDs))
	t.Cleanup(func() {
		cancel()
		for _, results := range clientErrors {
			if results == nil {
				continue
			}
			if err := waitServiceResult(results); err != nil {
				t.Errorf("recovery client shutdown: %v", err)
			}
		}
		if err := waitServiceResult(serverErrors); err != nil {
			t.Errorf("recovery server shutdown: %v", err)
		}
	})
	for index, clientID := range clientIDs {
		configuration := clientConfiguration
		configuration.Transport.ServerAddress = serverAddress
		configuration.Authentication = serverConfiguration.GovernedClients[clientID].Authentication
		configuration.Proxies = []config.ProxyConfig{{
			Name: "recovery", Type: proxyType,
			Local:  config.EndpointConfig{IP: "127.0.0.1", Port: localPorts[index]},
			Public: config.ProxyPublicConfig{Port: proxyPort},
		}}
		service := client.NewService(logging.New("test-mirror-recovery-client"), configuration)
		clientErrors[index] = make(chan error, 1)
		go func() { clientErrors[index] <- service.Run(ctx) }()
		waitForMirrorMembers(t, server, nil, nil, nil, proxyType, index+1)
	}
	return server, proxyAddress
}

func waitMirrorRecovery(t *testing.T, description string, ready func() bool) {
	t.Helper()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal(description)
		}
	}
}

// The observer reports every byte, so outage payload replay is distinguishable
// from successful forwarding of new input after a local service restart.
func startRecoveryTCPService(t *testing.T, address string, primary bool) (<-chan byte, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	observed := make(chan byte, 4096)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
			buffer := make([]byte, 1024)
			for {
				length, err := connection.Read(buffer)
				for _, value := range buffer[:length] {
					select {
					case observed <- value:
					case <-ctx.Done():
					}
				}
				if length != 0 {
					if !primary {
						for index := range buffer[:length] {
							buffer[index] = '!'
						}
					}
					_, _ = connection.Write(buffer[:length])
				}
				if err != nil {
					break
				}
			}
			stopClose()
			_ = connection.Close()
		}
	}()
	stop := func() {
		cancel()
		_ = listener.Close()
		<-done
	}
	t.Cleanup(stop)
	return observed, stop
}

func exchangeRecoveryTCP(t *testing.T, visitor net.Conn, observed <-chan byte, marker byte) {
	t.Helper()
	received, replied := false, false
	waitMirrorRecovery(t, "TCP member did not recover on the existing visitor connection", func() bool {
		if _, err := visitor.Write([]byte{marker}); err != nil {
			t.Fatal(err)
		}
		if err := visitor.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		var response [1]byte
		if _, err := visitor.Read(response[:]); err == nil {
			if response[0] == '!' {
				t.Fatal("non-Primary response reached visitor")
			}
			replied = replied || response[0] == marker
		} else if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
			t.Fatalf("visitor response direction was closed: %v", err)
		}
		for {
			select {
			case value := <-observed:
				if value != marker {
					t.Fatalf("replayed outage byte %q; expected only %q", value, marker)
				}
				received = true
			default:
				return received && replied
			}
		}
	})
}

func TestTCPMirrorLocalServiceRecovery(t *testing.T) {
	for _, transportType := range []transport.Type{transport.TypeTCP, transport.TypeQUIC} {
		for _, recoveringIndex := range []int{0, 1} {
			role := "primary"
			if recoveringIndex == 1 {
				role = "mirror"
			}
			t.Run(string(transportType)+"/"+role, func(t *testing.T) {
				addresses := [2]*net.TCPAddr{reserveTCPAddress(t), reserveTCPAddress(t)}
				stable, _ := startRecoveryTCPService(t, addresses[1-recoveringIndex].String(), recoveringIndex == 1)
				server, publicAddress := startMirrorRecoveryServer(t, protocol.ProxyTypeTCP, transportType,
					[2]uint16{uint16(addresses[0].Port), uint16(addresses[1].Port)})
				visitor := dialWithRetry(t, publicAddress, 5*time.Second)
				defer visitor.Close()
				if err := visitor.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
					t.Fatal(err)
				}
				// The other member observing input proves the initial failed dial has
				// completed and the public connection continues consuming traffic.
				if _, err := visitor.Write([]byte{'A'}); err != nil {
					t.Fatal(err)
				}
				waitMirrorRecovery(t, "healthy member stalled during local service outage", func() bool {
					select {
					case <-stable:
						return true
					default:
						return false
					}
				})
				observed, stop := startRecoveryTCPService(t, addresses[recoveringIndex].String(), recoveringIndex == 0)
				exchangeRecoveryTCP(t, visitor, observed, 'B')
				stop()
				waitMirrorRecovery(t, "failed member link was not released", func() bool {
					return server.linkBroker.SnapshotStats().Active == 1
				})
				if _, err := visitor.Write([]byte{'C'}); err != nil {
					t.Fatal(err)
				}
				waitMirrorRecovery(t, "healthy member stopped during restart", func() bool {
					select {
					case value := <-stable:
						return value == 'C'
					default:
						return false
					}
				})
				observed, _ = startRecoveryTCPService(t, addresses[recoveringIndex].String(), recoveringIndex == 0)
				exchangeRecoveryTCP(t, visitor, observed, 'D')
				if err := visitor.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				_ = visitor.SetReadDeadline(time.Now().Add(7 * time.Second))
				if _, err := io.Copy(io.Discard, visitor); err != nil {
					t.Fatalf("visitor half-close did not finish: %v", err)
				}
				waitMirrorRecovery(t, "mirror links remained after visitor EOF", func() bool {
					stats := server.linkBroker.SnapshotStats()
					return stats.Active == 0 && stats.Pending == 0
				})
			})
		}
	}
}

func TestUDPMirrorLocalServiceRecovery(t *testing.T) {
	for _, transportType := range []transport.Type{transport.TypeTCP, transport.TypeQUIC} {
		t.Run(string(transportType), func(t *testing.T) {
			addresses := [2]*net.UDPAddr{reserveUDPAddress(t), reserveUDPAddress(t)}
			_, publicAddress := startMirrorRecoveryServer(t, protocol.ProxyTypeUDP, transportType,
				[2]uint16{uint16(addresses[0].Port), uint16(addresses[1].Port)})
			visitor, err := net.Dial("udp", publicAddress)
			if err != nil {
				t.Fatal(err)
			}
			defer visitor.Close()
			// Exercise an unavailable destination before each start without
			// assuming the OS always delivers an ICMP error for a closed port.
			for _, marker := range []byte{'B', 'D'} {
				if _, err := visitor.Write([]byte{marker - 1}); err != nil {
					t.Fatal(err)
				}
				connections := make([]*net.UDPConn, 2)
				observed := make([]chan byte, 2)
				finished := make([]chan struct{}, 2)
				for index, address := range addresses {
					connections[index], err = net.ListenUDP("udp", address)
					if err != nil {
						t.Fatal(err)
					}
					connection := connections[index]
					t.Cleanup(func() { _ = connection.Close() })
					observed[index] = make(chan byte, 4096)
					finished[index] = make(chan struct{})
					go func() {
						defer close(finished[index])
						var payload [1]byte
						for {
							_, source, err := connection.ReadFromUDP(payload[:])
							if err != nil {
								return
							}
							observed[index] <- payload[0]
							if index == 1 {
								payload[0] = '!'
							}
							_, _ = connection.WriteToUDP(payload[:], source)
						}
					}()
				}
				seen := [2]bool{}
				replied := false
				waitMirrorRecovery(t, "UDP services did not recover for the same visitor source", func() bool {
					if _, err := visitor.Write([]byte{marker}); err != nil {
						t.Fatal(err)
					}
					_ = visitor.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
					var response [1]byte
					if _, err := visitor.Read(response[:]); err == nil {
						if response[0] == '!' {
							t.Fatal("UDP non-Primary response reached visitor")
						}
						replied = replied || response[0] == marker
					}
					for index := range observed {
						select {
						case value := <-observed[index]:
							seen[index] = seen[index] || value == marker
						default:
						}
					}
					return replied && seen[0] && seen[1]
				})
				for index, connection := range connections {
					_ = connection.Close()
					<-finished[index]
				}
			}
		})
	}
}
