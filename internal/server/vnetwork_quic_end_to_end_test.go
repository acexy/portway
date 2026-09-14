package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
	"github.com/acexy/portway/internal/transport/quic"
	"github.com/acexy/portway/internal/vnet"
)

func TestVNetPacketPoolOverQUICEndToEnd(t *testing.T) {
	for _, packetProtocol := range []uint8{6, 17} {
		name := "TCP"
		if packetProtocol == 17 {
			name = "UDP"
		}
		t.Run(name, func(t *testing.T) {
			testVNetPacketPoolOverQUIC(t, packetProtocol)
		})
	}
}

func testVNetPacketPoolOverQUIC(t *testing.T, packetProtocol uint8) {
	t.Helper()
	certificateFile, keyFile := writeQUICServerCertificate(t)
	address := reserveUDPAddress(t)
	token := "vnet-quic-test-token-with-at-least-32-bytes"
	snapshot, err := authentication.NewSnapshot([]authentication.Record{{
		Context: authentication.Context{Mode: authentication.ModeManaged, ClientID: "client-a"},
		Token:   token,
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := quic.NewServer(ctx, quic.ServerConfig{
		Address: address.String(), CertFile: certificateFile, KeyFile: keyFile,
		Credentials: authentication.NewStore(snapshot),
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := quic.NewClient(quic.ClientConfig{
		Address: address.String(), ServerName: "localhost", CAFile: certificateFile, Token: token,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	control, err := server.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if control.Role != protocol.RoleControl {
		t.Fatalf("unexpected QUIC control role %d", control.Role)
	}

	broker := vnet.NewPoolBroker()
	defer broker.Close()
	spec := vnet.PoolSpec{
		ClientID: "client-a", SessionID: "session-a", TransportGeneration: 1,
		VirtualIP: "172.20.0.2", PoolGeneration: 1, ChannelCount: 4,
		MTU: 1280, WriteTimeout: time.Second, Authentication: control.Authentication,
	}
	offers, err := broker.Prepare(spec, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientChannels := make([]net.Conn, len(offers))
	active := make(chan *vnet.Pool, 1)
	bindResults := make(chan error, len(offers))
	for index, offer := range offers {
		stream, openError := session.OpenDataStream(ctx)
		if openError != nil {
			t.Fatal(openError)
		}
		clientChannels[index] = stream
		binding := protocol.BindVNetChannel{
			ClientID: spec.ClientID, SessionID: spec.SessionID,
			TransportGeneration: spec.TransportGeneration, VirtualIP: spec.VirtualIP,
			PoolGeneration: spec.PoolGeneration, ChannelIndex: offer.ChannelIndex,
			ChannelCount: spec.ChannelCount, Ticket: offer.Ticket,
		}
		if err := protocol.WriteControl(stream, protocol.MessageBindVNetChannel, binding); err != nil {
			t.Fatal(err)
		}
		inbound, acceptError := server.Accept(ctx)
		if acceptError != nil {
			t.Fatal(acceptError)
		}
		var envelope protocol.Envelope
		envelope, err = protocol.ReadControl(inbound.Stream)
		if err != nil {
			t.Fatal(err)
		}
		var receivedBinding protocol.BindVNetChannel
		if envelope.Type != protocol.MessageBindVNetChannel {
			t.Fatalf("unexpected VNet bind message %q", envelope.Type)
		}
		if err := protocol.DecodePayload(envelope, &receivedBinding); err != nil {
			t.Fatal(err)
		}
		go func() {
			bindResults <- broker.Bind(ctx, inbound.Stream, receivedBinding, inbound.Authentication, func() {
				_ = protocol.WriteControl(inbound.Stream, protocol.MessageVNetBindResult, protocol.VNetBindResult{
					PoolGeneration: receivedBinding.PoolGeneration,
					ChannelIndex:   receivedBinding.ChannelIndex,
					Status:         protocol.LinkStatusAccepted,
				})
			}, func(pool *vnet.Pool) { active <- pool })
		}()
		if _, err := protocol.ReadControl(stream); err != nil {
			t.Fatal(err)
		}
	}
	var pool *vnet.Pool
	select {
	case pool = <-active:
	case <-time.After(time.Second):
		t.Fatal("VNet QUIC pool did not activate")
	}

	packet := vnetTestPacket(packetProtocol)
	flow, err := vnet.ParseIPv4(packet)
	if err != nil {
		t.Fatal(err)
	}
	channelIndex, err := vnet.ChannelIndex(flow, spec.ChannelCount)
	if err != nil {
		t.Fatal(err)
	}
	serverWrite := make(chan error, 1)
	go func() { serverWrite <- pool.Send(packet, channelIndex) }()
	received, err := vnet.ReadPacket(clientChannels[channelIndex], spec.MTU)
	if err != nil || !bytes.Equal(received, packet) {
		t.Fatalf("server-to-client VNet packet failed: packet=%v err=%v", received, err)
	}
	if err := <-serverWrite; err != nil {
		t.Fatal(err)
	}

	serverRead := make(chan []byte, 1)
	readerResult := make(chan error, 1)
	go func() {
		readerResult <- pool.RunReaders(func(received []byte) error {
			serverRead <- received
			return net.ErrClosed
		})
	}()
	if err := vnet.WritePacket(clientChannels[channelIndex], packet, spec.MTU); err != nil {
		t.Fatal(err)
	}
	select {
	case received = <-serverRead:
		if !bytes.Equal(received, packet) {
			t.Fatal("client-to-server VNet packet changed")
		}
	case <-time.After(time.Second):
		t.Fatal("client-to-server VNet packet timed out")
	}
	<-readerResult
	for range offers {
		select {
		case <-bindResults:
		case <-time.After(time.Second):
			t.Fatal("VNet QUIC binding did not stop")
		}
	}
}

func vnetTestPacket(packetProtocol uint8) []byte {
	length := 40
	if packetProtocol == 17 {
		length = 28
	}
	packet := make([]byte, length)
	packet[0], packet[8], packet[9] = 0x45, 64, packetProtocol
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	copy(packet[12:16], []byte{172, 20, 0, 3})
	copy(packet[16:20], []byte{172, 20, 0, 2})
	binary.BigEndian.PutUint16(packet[20:22], 443)
	binary.BigEndian.PutUint16(packet[22:24], 50000)
	if packetProtocol == 6 {
		packet[32], packet[33] = 0x50, 0x02
	} else {
		binary.BigEndian.PutUint16(packet[24:26], 8)
	}
	return packet
}
