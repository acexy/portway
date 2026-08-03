package ipfilter

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gaissmai/bart"

	"github.com/acexy/portway/internal/logging"
)

func TestNewLoadsIPAndCIDRRules(t *testing.T) {
	rulesPath := writeRules(t, `
# blocked networks
192.0.2.0/24
192.0.2.0/24
2001:db8::10
198.51.100.7
`)
	filter, err := New(
		context.Background(),
		logging.New("ip-filter-test"),
		rulesPath,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer filter.Close()

	testCases := []struct {
		address string
		denied  bool
	}{
		{address: "192.0.2.50", denied: true},
		{address: "198.51.100.7", denied: true},
		{address: "198.51.100.8", denied: false},
		{address: "2001:db8::10", denied: true},
		{address: "2001:db8::11", denied: false},
	}
	for _, testCase := range testCases {
		address := netip.MustParseAddr(testCase.address)
		if actual := filter.Denied(address); actual != testCase.denied {
			t.Fatalf(
				"Denied(%s) = %t, want %t",
				address,
				actual,
				testCase.denied,
			)
		}
	}
	if actual := filter.snapshot.Load().count; actual != 3 {
		t.Fatalf("rule count = %d, want 3", actual)
	}
}

func TestDeniedWarningsAreGloballyBounded(t *testing.T) {
	filter := &Filter{logger: logging.New("ip_filter")}
	filter.snapshot.Store(&ruleSnapshot{prefixes: &bart.Lite{}})
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	filter.snapshot.Load().prefixes.Insert(prefix)

	if !filter.DeniedFor(netip.MustParseAddr("192.0.2.1"), "tcp_proxy") {
		t.Fatal("first source was not denied")
	}
	if !filter.DeniedFor(netip.MustParseAddr("192.0.2.2"), "udp_proxy") {
		t.Fatal("second source was not denied")
	}
	if pending := filter.deniedSinceLog.Load(); pending != 1 {
		t.Fatalf("suppressed deny count = %d, want 1", pending)
	}
}

func TestNewRejectsInvalidInitialRules(t *testing.T) {
	rulesPath := writeRules(t, "192.0.2.0/24\nnot-an-address\n")
	filter, err := New(
		context.Background(),
		logging.New("ip-filter-test"),
		rulesPath,
	)
	if err == nil {
		filter.Close()
		t.Fatal("New() error = nil, want invalid rule failure")
	}
}

func TestReloadIsAtomicAndClosesNewlyDeniedSources(t *testing.T) {
	rulesPath := writeRules(t, "198.51.100.0/24\n")
	filter, err := New(
		context.Background(),
		logging.New("ip-filter-test"),
		rulesPath,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer filter.Close()

	var closed atomic.Bool
	release, allowed := filter.Register(
		netip.MustParseAddr("192.0.2.10"),
		func() { closed.Store(true) },
	)
	if !allowed {
		t.Fatal("Register() rejected an initially allowed source")
	}
	defer release()

	if err := os.WriteFile(rulesPath, []byte("invalid\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(invalid) error = %v", err)
	}
	filter.reload()
	if filter.Denied(netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("invalid reload replaced the previous snapshot")
	}
	if closed.Load() {
		t.Fatal("invalid reload closed an allowed connection")
	}

	if err := os.WriteFile(rulesPath, []byte("192.0.2.0/24\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(valid) error = %v", err)
	}
	filter.reload()
	if !filter.Denied(netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("valid reload did not install the new snapshot")
	}
	if !closed.Load() {
		t.Fatal("valid reload did not close a newly denied source")
	}
}

func TestWrappedListenerClosesTrackedConnectionAfterReload(t *testing.T) {
	rulesPath := writeRules(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	filter, err := New(ctx, logging.New("ip-filter-test"), rulesPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer filter.Close()

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	listener := WrapListener(rawListener, filter)
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, acceptError := listener.Accept()
		if acceptError != nil {
			acceptErrors <- acceptError
			return
		}
		accepted <- connection
	}()
	clientConnection, err := net.Dial("tcp", rawListener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer clientConnection.Close()

	var serverConnection net.Conn
	select {
	case serverConnection = <-accepted:
	case acceptError := <-acceptErrors:
		t.Fatalf("Accept() error = %v", acceptError)
	case <-time.After(time.Second):
		t.Fatal("Accept() did not return")
	}
	defer serverConnection.Close()

	if err := os.WriteFile(rulesPath, []byte("127.0.0.1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	filter.reload()
	if err := serverConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("SetReadDeadline() error = %v, want net.ErrClosed", err)
		}
		return
	}
	var buffer [1]byte
	if _, err := serverConnection.Read(buffer[:]); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read() error = %v, want net.ErrClosed", err)
	}
}

func TestHTTPHandlerUsesConfiguredSingleIPHeader(t *testing.T) {
	rulesPath := writeRules(t, "192.0.2.0/24\n")
	filter, err := New(
		context.Background(),
		logging.New("ip-filter-test"),
		rulesPath,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer filter.Close()

	testCases := []struct {
		name    string
		values  []string
		handled bool
	}{
		{name: "allowed", values: []string{"198.51.100.10"}, handled: true},
		{name: "denied", values: []string{"192.0.2.10"}},
		{name: "missing"},
		{name: "list", values: []string{"198.51.100.10, 192.0.2.10"}},
		{
			name:    "allowed list",
			values:  []string{"198.51.100.10, 203.0.113.20"},
			handled: true,
		},
		{
			name:    "repeated allowed values",
			values:  []string{"198.51.100.10", "203.0.113.20"},
			handled: true,
		},
		{name: "empty list item", values: []string{"198.51.100.10, "}},
		{name: "partially invalid", values: []string{"198.51.100.10, invalid"}},
		{name: "invalid", values: []string{"not-an-ip"}},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			serverConnection, clientConnection := net.Pipe()
			defer serverConnection.Close()
			defer clientConnection.Close()
			var handled atomic.Bool
			handler := HTTPHandler(
				filter,
				"X-Real-Ip",
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					handled.Store(true)
				}),
			)
			request := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			for _, value := range testCase.values {
				request.Header.Add("X-Real-Ip", value)
			}
			request = request.WithContext(
				HTTPConnectionContext(request.Context(), serverConnection),
			)
			handler.ServeHTTP(httptest.NewRecorder(), request)
			if actual := handled.Load(); actual != testCase.handled {
				t.Fatalf("handler called = %t, want %t", actual, testCase.handled)
			}
		})
	}
}

func writeRules(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deny.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
