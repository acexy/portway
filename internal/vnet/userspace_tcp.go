package vnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	userspaceTCPNICID                = 1
	userspaceTCPPacketQueue          = 256
	userspaceTCPMaximumHandshakes    = 256
	userspaceTCPMaximumConnections   = 1024
	userspaceTCPMaximumFlows         = 65536
	userspaceTCPFlowIdle             = 5 * time.Minute
	userspaceTCPDialTimeout          = 5 * time.Second
	userspaceUDPMaximumAssociations = 4096
	userspaceUDPAssociationIdle     = time.Minute
	userspaceUDPMaximumPayload      = 65507
)

// UserspaceTCP terminates remote-initiated TCP and UDP flows and forwards them to loopback.
type UserspaceTCP struct {
	context     context.Context
	cancel      context.CancelFunc
	stack       *stack.Stack
	link        *channel.Endpoint
	localIP     netip.Addr
	output      func([]byte) error
	mutex       sync.Mutex
	flows       map[flowKey]time.Time
	connections chan struct{}
	associations chan struct{}
	waitGroup   sync.WaitGroup
	closeOnce   sync.Once
}

// NewUserspaceTCP creates one bounded IPv4 TCP/UDP stack for a VNet endpoint.
func NewUserspaceTCP(
	parent context.Context,
	localIP netip.Addr,
	prefixLength int,
	mtu uint16,
	output func([]byte) error,
) (*UserspaceTCP, error) {
	if !localIP.Is4() || prefixLength < 0 || prefixLength > 32 || mtu < 576 || output == nil {
		return nil, errors.New("invalid VNet userspace TCP/IP configuration")
	}
	ctx, cancel := context.WithCancel(parent)
	networkStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	linkEndpoint := channel.New(userspaceTCPPacketQueue, uint32(mtu), "")
	if err := networkStack.CreateNIC(userspaceTCPNICID, linkEndpoint); err != nil {
		cancel()
		return nil, fmt.Errorf("create VNet userspace TCP/IP NIC: %s", err)
	}
	address := localIP.As4()
	if err := networkStack.AddProtocolAddress(userspaceTCPNICID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: tcpip.AddrFrom4(address), PrefixLen: prefixLength,
		},
	}, stack.AddressProperties{}); err != nil {
		cancel()
		linkEndpoint.Close()
		return nil, fmt.Errorf("assign VNet userspace TCP/IP address: %s", err)
	}
	networkStack.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         userspaceTCPNICID,
	}})
	runtime := &UserspaceTCP{
		context: ctx, cancel: cancel, stack: networkStack, link: linkEndpoint,
		localIP: localIP, output: output, flows: make(map[flowKey]time.Time),
		connections: make(chan struct{}, userspaceTCPMaximumConnections),
		associations: make(chan struct{}, userspaceUDPMaximumAssociations),
	}
	forwarder := tcp.NewForwarder(
		networkStack, 0, userspaceTCPMaximumHandshakes, runtime.forward,
	)
	networkStack.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
	udpForwarder := udp.NewForwarder(networkStack, runtime.forwardUDP)
	networkStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	runtime.waitGroup.Go(runtime.writePackets)
	runtime.waitGroup.Go(runtime.expireFlows)
	return runtime, nil
}

// Handle injects packets owned by a remote-initiated TCP flow.
func (runtime *UserspaceTCP) Handle(packet []byte) bool {
	flow, err := ParseIPv4(packet)
	if err != nil || (flow.Protocol != protocolTCP && flow.Protocol != protocolUDP) ||
		flow.DestinationIP != runtime.localIP {
		return false
	}
	key := makeFlowKey(flow)
	now := time.Now()
	runtime.mutex.Lock()
	_, owned := runtime.flows[key]
	if !owned && (flow.Protocol == protocolUDP || flow.IsTCPStart()) &&
		len(runtime.flows) < userspaceTCPMaximumFlows {
		owned = true
	}
	if owned {
		if flow.IsTCPReset() {
			delete(runtime.flows, key)
		} else {
			runtime.flows[key] = now.Add(userspaceTCPFlowIdle)
		}
	}
	runtime.mutex.Unlock()
	if !owned {
		return false
	}
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	runtime.link.InjectInbound(ipv4.ProtocolNumber, packetBuffer)
	packetBuffer.DecRef()
	return true
}

func (runtime *UserspaceTCP) forwardUDP(request *udp.ForwarderRequest) bool {
	select {
	case runtime.associations <- struct{}{}:
	case <-runtime.context.Done():
		return false
	default:
		return false
	}
	queue := &waiter.Queue{}
	endpoint, endpointError := request.CreateEndpoint(queue)
	if endpointError != nil {
		<-runtime.associations
		return false
	}
	remote := gonet.NewUDPConn(queue, endpoint)
	port := request.ID().LocalPort
	local, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP: net.ParseIP("127.0.0.1"), Port: int(port),
	})
	if err != nil {
		_ = remote.Close()
		<-runtime.associations
		return true
	}
	runtime.waitGroup.Go(func() {
		defer func() { <-runtime.associations }()
		defer remote.Close()
		defer local.Close()
		forwardUDPAssociation(runtime.context, remote, local)
	})
	return true
}

func forwardUDPAssociation(ctx context.Context, remote, local net.Conn) {
	associationContext, cancel := context.WithCancel(ctx)
	defer cancel()
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	var waitGroup sync.WaitGroup
	copyDatagrams := func(destination, source net.Conn) {
		defer waitGroup.Done()
		buffer := make([]byte, userspaceUDPMaximumPayload)
		for {
			deadline := time.Unix(0, lastActivity.Load()).Add(userspaceUDPAssociationIdle)
			if err := source.SetReadDeadline(deadline); err != nil {
				cancel()
				return
			}
			count, err := source.Read(buffer)
			if err != nil {
				cancel()
				return
			}
			lastActivity.Store(time.Now().UnixNano())
			if _, err := destination.Write(buffer[:count]); err != nil {
				cancel()
				return
			}
		}
	}
	waitGroup.Add(2)
	go copyDatagrams(local, remote)
	go copyDatagrams(remote, local)
	<-associationContext.Done()
	_ = remote.SetDeadline(time.Now())
	_ = local.SetDeadline(time.Now())
	waitGroup.Wait()
}

func (runtime *UserspaceTCP) forward(request *tcp.ForwarderRequest) {
	select {
	case runtime.connections <- struct{}{}:
	case <-runtime.context.Done():
		request.Complete(true)
		return
	default:
		request.Complete(true)
		return
	}
	defer func() { <-runtime.connections }()
	port := request.ID().LocalPort
	dialer := net.Dialer{Timeout: userspaceTCPDialTimeout}
	local, err := dialer.DialContext(
		runtime.context,
		"tcp4",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))),
	)
	if err != nil {
		request.Complete(true)
		return
	}
	queue := &waiter.Queue{}
	endpoint, endpointError := request.CreateEndpoint(queue)
	if endpointError != nil {
		request.Complete(true)
		_ = local.Close()
		return
	}
	request.Complete(false)
	remote := gonet.NewTCPConn(queue, endpoint)
	_, _ = proxytcp.Forward(runtime.context, remote, local)
}

func (runtime *UserspaceTCP) writePackets() {
	for {
		packet := runtime.link.ReadContext(runtime.context)
		if packet == nil {
			return
		}
		view := packet.ToView()
		data := append([]byte(nil), view.AsSlice()...)
		view.Release()
		packet.DecRef()
		_ = runtime.output(data)
	}
}

func (runtime *UserspaceTCP) expireFlows() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-runtime.context.Done():
			return
		case now := <-ticker.C:
			runtime.mutex.Lock()
			for key, expiresAt := range runtime.flows {
				if !now.Before(expiresAt) {
					delete(runtime.flows, key)
				}
			}
			runtime.mutex.Unlock()
		}
	}
}

// Close terminates the userspace stack and every forwarded connection.
func (runtime *UserspaceTCP) Close() error {
	runtime.closeOnce.Do(func() {
		runtime.cancel()
		runtime.link.Close()
		runtime.stack.Close()
		runtime.stack.Wait()
		runtime.waitGroup.Wait()
	})
	return nil
}
