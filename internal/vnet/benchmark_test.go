package vnet

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/config"
	"github.com/acexy/portway/internal/vnet/internal/flowcontrol"
	"github.com/acexy/portway/internal/vnet/internal/testpacket"
	packetdata "github.com/acexy/portway/internal/vnet/packet"
)

func BenchmarkVNetPacketFrame(b *testing.B) {
	packet := testpacket.IPv4(packetdata.ProtocolUDP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 53)
	buffer := make([]byte, packetFrameHeaderSize+len(packet))
	writer := fixedBufferWriter{buffer: buffer}
	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	for b.Loop() {
		writer.offset = 0
		if err := WritePacket(&writer, packet, 1280); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVNetPoolParallelFlows(b *testing.B) {
	for _, channelCount := range []int{1, 2, 4, 8} {
		b.Run(string(rune('0'+channelCount))+"Channels", func(b *testing.B) {
			pool, peers := benchmarkPool(b, channelCount)
			packet := testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 443)
			b.ReportAllocs()
			b.SetBytes(int64(len(packet)))
			b.RunParallel(func(parallel *testing.PB) {
				index := uint8(0)
				for parallel.Next() {
					if err := pool.Send(packet, index%uint8(channelCount)); err != nil {
						b.Error(err)
						return
					}
					index++
				}
			})
			pool.Close()
			for _, peer := range peers {
				peer.Close()
			}
		})
	}
}

func BenchmarkVNetRouterDispatch(b *testing.B) {
	configuration := config.DefaultServer().VirtualNetwork
	configuration.Enabled = true
	configuration.PacketChannels = 4
	configuration.Nodes = []config.VNetNodeConfig{
		{ClientID: "source", IP: "172.20.0.2"},
		{ClientID: "target", IP: "172.20.0.3", Ports: config.VNetPortPermissions{
			UDP: config.ForwardPortPermission{PortRanges: []config.PortRange{{Start: 53, End: 53}}},
		}},
	}
	router, err := NewRouter(configuration, 65536)
	if err != nil {
		b.Fatal(err)
	}
	packet := testpacket.IPv4(packetdata.ProtocolUDP, [4]byte{172, 20, 0, 2}, 50000, [4]byte{172, 20, 0, 3}, 53)
	now := time.Now()
	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	for b.Loop() {
		if _, err := router.RouteClientPacket("source", packet, now); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkPool(b *testing.B, channelCount int) (*Pool, []net.Conn) {
	b.Helper()
	channels := make([]net.Conn, channelCount)
	peers := make([]net.Conn, channelCount)
	writers := make([]*PacketWriter, channelCount)
	for index := range channelCount {
		channels[index], peers[index] = net.Pipe()
		writers[index] = NewPacketWriter(context.Background(), channels[index], 1280, time.Second)
		go func(peer net.Conn) { _, _ = io.Copy(io.Discard, peer) }(peers[index])
	}
	return &Pool{
		spec:     PoolSpec{MTU: 1280, WriteTimeout: time.Second},
		channels: channels, writers: writers, done: make(chan struct{}),
	}, peers
}

type fixedBufferWriter struct {
	buffer []byte
	offset int
}

func (writer *fixedBufferWriter) Write(value []byte) (int, error) {
	written := copy(writer.buffer[writer.offset:], value)
	writer.offset += written
	return written, nil
}

// This isolates router lock contention; it is not an end-to-end throughput claim.
func BenchmarkVNetRouterParallelEstablished(b *testing.B) {
	router, err := NewRouter(testVNetConfiguration(), 65536)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	packets := make([][]byte, 64)
	for index := range packets {
		packets[index] = testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 2}, uint16(10000+index), [4]byte{172, 20, 0, 3}, 8080)
		if _, err := router.RouteClientPacket("client-a", packets[index], now); err != nil {
			b.Fatal(err)
		}
		packets[index][33] = 0x10
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(iterations *testing.PB) {
		index := 0
		for iterations.Next() {
			if _, err := router.RouteClientPacket("client-a", packets[index%len(packets)], now); err != nil {
				b.Error(err)
				return
			}
			index++
		}
	})
}

func BenchmarkVNetFlowAdmissionChurn(b *testing.B) {
	var admission flowcontrol.Admission
	packet := testpacket.IPv4(packetdata.ProtocolTCP, [4]byte{172, 20, 0, 2}, 10000, [4]byte{172, 20, 0, 3}, 8080)
	flow, err := packetdata.ParseIPv4(packet)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		now = now.Add(10 * time.Millisecond)
		if err := admission.Admit(flow, now, 65536); err != nil {
			b.Fatal(err)
		}
		admission.Release(flow.SourceIP, flow.DestinationIP)
	}
}
