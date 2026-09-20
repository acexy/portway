package vnet

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func TestUserspaceReturnsHostUDPRepliesToTUN(t *testing.T) {
	runtime, err := NewUserspaceTCP(context.Background(), netip.MustParseAddr("172.20.0.2"), 16, 1280, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	request := testIPv4Packet(protocolUDP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 53)
	reply := testIPv4Packet(protocolUDP, [4]byte{172, 20, 0, 3}, 53, [4]byte{172, 20, 0, 2}, 50000)
	if !runtime.ObserveHostPacket(request) {
		t.Fatal("host request was rejected")
	}
	if runtime.Handle(reply) {
		t.Fatal("host UDP reply was captured by loopback")
	}
	if len(runtime.flows) != 0 {
		t.Fatal("host reply created a loopback association")
	}
}

func TestUserspaceCapacityRejectsWithoutTUNFallback(t *testing.T) {
	runtime, err := NewUserspaceTCP(context.Background(), netip.MustParseAddr("172.20.0.2"), 16, 1280, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	runtime.mutex.Lock()
	for index := range userspaceTCPMaximumFlows {
		runtime.hostFlows[flowKey{firstPort: uint16(index)}] = time.Now().Add(time.Hour)
	}
	runtime.mutex.Unlock()
	for _, protocol := range []uint8{protocolUDP, protocolTCP} {
		packet := testIPv4Packet(protocol, [4]byte{172, 20, 0, 3}, 50000, [4]byte{172, 20, 0, 2}, 8080)
		if !runtime.Handle(packet) {
			t.Fatal("capacity rejection fell back to TUN")
		}
	}
	if len(runtime.flows) != 0 {
		t.Fatal("capacity rejection allocated a loopback flow")
	}
}

// scriptedDatagramConn lets the test deliver an old read timeout after opposite traffic.
type scriptedDatagramConn struct {
	reads     chan error
	writes    chan struct{}
	deadlines chan time.Time
	closed    chan struct{}
	once      sync.Once
}

func newScriptedDatagramConn() *scriptedDatagramConn {
	return &scriptedDatagramConn{make(chan error), make(chan struct{}, 4), make(chan time.Time, 4), make(chan struct{}), sync.Once{}}
}

func (connection *scriptedDatagramConn) Read(packet []byte) (int, error) {
	select {
	case err := <-connection.reads:
		if err != nil {
			return 0, err
		}
		packet[0] = 1
		return 1, nil
	case <-connection.closed:
		return 0, net.ErrClosed
	}
}

func (connection *scriptedDatagramConn) Write(packet []byte) (int, error) {
	connection.writes <- struct{}{}
	return len(packet), nil
}

func (connection *scriptedDatagramConn) Close() error {
	connection.once.Do(func() { close(connection.closed) })
	return nil
}

func (connection *scriptedDatagramConn) SetReadDeadline(deadline time.Time) error {
	connection.deadlines <- deadline
	return nil
}

func (connection *scriptedDatagramConn) SetDeadline(time.Time) error { return connection.Close() }
func (*scriptedDatagramConn) SetWriteDeadline(time.Time) error       { return nil }
func (*scriptedDatagramConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (*scriptedDatagramConn) RemoteAddr() net.Addr                   { return &net.UDPAddr{} }

func TestUDPAssociationRechecksActivityAfterOldDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remote, local := newScriptedDatagramConn(), newScriptedDatagramConn()
	finished := make(chan struct{})
	go func() {
		forwardUDPAssociation(ctx, remote, local)
		close(finished)
	}()
	<-remote.deadlines
	<-local.deadlines
	remote.reads <- nil
	<-local.writes
	local.reads <- os.ErrDeadlineExceeded
	select {
	case <-local.deadlines:
		// The previously blocked reader must be rearmed after opposite activity.
	case <-finished:
		t.Fatal("active association was closed by an old deadline")
	case <-time.After(time.Second):
		t.Fatal("active association did not resume reading")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("association did not cancel")
	}
}

func TestUserspaceExpiryCancelsOnlyCurrentOwner(t *testing.T) {
	runtime, err := NewUserspaceTCP(context.Background(), netip.MustParseAddr("172.20.0.3"), 16, 1150, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	packet := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	flow, _ := ParseIPv4(packet)
	key := makeFlowKey(flow)
	runtime.mutex.Lock()
	runtime.flows[key] = time.Now().Add(time.Minute)
	runtime.mutex.Unlock()
	ctx, owner := runtime.ownFlow(key)
	if owner == nil {
		t.Fatal("flow owner missing")
	}
	runtime.expireFlowsAt(time.Now().Add(2 * time.Minute))
	select {
	case <-ctx.Done():
	default:
		t.Fatal("expired flow did not cancel proxy")
	}
	runtime.mutex.Lock()
	runtime.flows[key] = time.Now().Add(time.Minute)
	runtime.mutex.Unlock()
	replacementContext, replacement := runtime.ownFlow(key)
	runtime.releaseFlow(key, owner)
	select {
	case <-replacementContext.Done():
		t.Fatal("old completion cancelled replacement")
	default:
	}
	runtime.releaseFlow(key, replacement)
	if len(runtime.flowCancels) != 0 || len(runtime.flows) != 0 {
		t.Fatal("completed flow retained ownership")
	}
}

func TestUserspaceOutputRefreshesFlowAndExpiredACKCannotRevive(t *testing.T) {
	runtime, err := NewUserspaceTCP(context.Background(), netip.MustParseAddr("172.20.0.3"), 16, 1150, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	packet := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 3}, 8080, [4]byte{172, 20, 0, 2}, 50000)
	packet[33] = 0x10
	flow, _ := ParseIPv4(packet)
	key := makeFlowKey(flow)
	before := time.Now()
	runtime.mutex.Lock()
	runtime.flows[key] = before.Add(time.Second)
	runtime.mutex.Unlock()
	runtime.observeOutput(packet)
	runtime.mutex.Lock()
	expires := runtime.flows[key]
	runtime.flows[key] = before.Add(-time.Second)
	runtime.mutex.Unlock()
	if expires.Before(before.Add(userspaceTCPFlowIdle)) {
		t.Fatal("outgoing activity did not refresh flow")
	}
	incoming := testIPv4Packet(protocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 8080)
	incoming[33] = 0x10
	if !runtime.Handle(incoming) {
		t.Fatal("expired ACK fell back to TUN")
	}
	runtime.mutex.Lock()
	_, exists := runtime.flows[key]
	runtime.mutex.Unlock()
	if exists {
		t.Fatal("expired ACK recreated flow")
	}
}
