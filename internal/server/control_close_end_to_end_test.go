package server

import (
	"context"
	"testing"
	"time"

	toolkitlogger "github.com/acexy/golang-toolkit/logger"
	"github.com/sirupsen/logrus"

	"github.com/acexy/portway/internal/client"
	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/transport"
)

type closeSessionLogHook struct {
	messages chan string
}

func (*closeSessionLogHook) Levels() []logrus.Level { return logrus.AllLevels }

func (hook *closeSessionLogHook) Fire(entry *logrus.Entry) error {
	if entry.Data["component"] == "close-regression-client" {
		switch entry.Message {
		case "control session established", "control session close acknowledged", "control session close unconfirmed":
			hook.messages <- entry.Message
		}
	}
	return nil
}

func TestClientShutdownAcknowledgedOverTCPAndQUIC(t *testing.T) {
	activeLogger := toolkitlogger.Logrus()
	originalLevel := activeLogger.GetLevel()
	originalHooks := activeLogger.ReplaceHooks(make(logrus.LevelHooks))
	t.Cleanup(func() {
		activeLogger.ReplaceHooks(originalHooks)
		activeLogger.SetLevel(originalLevel)
	})
	activeLogger.SetLevel(logrus.InfoLevel)
	hook := &closeSessionLogHook{messages: make(chan string, 32)}
	activeLogger.AddHook(hook)

	for _, transportType := range []transport.Type{transport.TypeTCP, transport.TypeQUIC} {
		t.Run(string(transportType), func(t *testing.T) {
			serverConfiguration, clientConfiguration := benchmarkTransportConfigurations(t, transportType)
			serverConfiguration.Proxies.BindIP = "127.0.0.1"
			clientConfiguration.Authentication.ClientID = "close-regression-client"
			clientConfiguration.Proxies = []config.ProxyConfig{{
				Name: "close-test", Type: "tcp",
				Local:  config.EndpointConfig{IP: "127.0.0.1", Port: 9},
				Public: config.ProxyPublicConfig{Port: uint16(reserveTCPAddress(t).Port)},
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			serverResult := make(chan error, 1)
			service := NewService(logging.New("close-regression-server"), serverConfiguration)
			go func() { serverResult <- service.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				if err := waitServiceResult(serverResult); err != nil {
					t.Errorf("stop server: %v", err)
				}
			})

			// Reuse the identity and binding to also check that acknowledgment means
			// the previous session no longer reserves either resource.
			for range 3 {
				clientContext, cancelClient := context.WithCancel(ctx)
				clientDone := make(chan struct{})
				clientResult := make(chan error, 1)
				clientService := client.NewService(logging.New("close-regression-client"), clientConfiguration)
				go func() {
					defer close(clientDone)
					clientResult <- clientService.Run(clientContext)
				}()
				t.Cleanup(func() { cancelClient(); <-clientDone })
				select {
				case message := <-hook.messages:
					if message != "control session established" {
						t.Fatalf("unexpected startup message: %s", message)
					}
				case err := <-clientResult:
					t.Fatalf("client stopped before establishment: %v", err)
				case <-ctx.Done():
					t.Fatal("client did not establish a session")
				}
				cancelClient()
				if err := waitServiceResult(clientResult); err != nil {
					t.Fatalf("stop client: %v", err)
				}
				select {
				case message := <-hook.messages:
					if message != "control session close acknowledged" {
						t.Fatalf("shutdown was not acknowledged: %s", message)
					}
				default:
					t.Fatal("client stopped without confirming session closure")
				}
			}
		})
	}
}
