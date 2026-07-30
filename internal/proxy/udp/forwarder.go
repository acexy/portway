package udp

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

// Forward exchanges framed datagrams between one Data Stream and one connected
// local UDP socket.
func Forward(
	ctx context.Context,
	stream net.Conn,
	local net.Conn,
	maxDatagramSize int,
	writeTimeout time.Duration,
) error {
	stopContextClose := context.AfterFunc(ctx, func() {
		stream.Close()
		local.Close()
	})
	defer stopContextClose()
	defer stream.Close()
	defer local.Close()

	results := make(chan error, 2)
	go func() {
		for {
			payload, err := ReadDatagram(stream, maxDatagramSize)
			if err != nil {
				results <- err
				return
			}
			written, err := local.Write(payload)
			if err != nil {
				results <- err
				return
			}
			if written != len(payload) {
				results <- io.ErrShortWrite
				return
			}
		}
	}()
	go func() {
		buffer := make([]byte, maxDatagramSize+1)
		for {
			length, err := local.Read(buffer)
			if err != nil {
				results <- err
				return
			}
			if length > maxDatagramSize {
				continue
			}
			if err := stream.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				results <- err
				return
			}
			if err := WriteDatagram(stream, buffer[:length], maxDatagramSize); err != nil {
				results <- err
				return
			}
		}
	}()

	first := <-results
	stream.Close()
	local.Close()
	second := <-results
	return errors.Join(first, second)
}
