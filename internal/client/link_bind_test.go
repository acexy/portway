package client

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/acexy/portway/internal/protocol"
)

type bindingTestStream struct {
	net.Conn
	response     *bytes.Reader
	deadlines    []time.Time
	failDeadline int
}

func (stream *bindingTestStream) Read(payload []byte) (int, error) {
	return stream.response.Read(payload)
}
func (stream *bindingTestStream) Write(payload []byte) (int, error) { return len(payload), nil }
func (stream *bindingTestStream) CloseWrite() error                 { return nil }
func (stream *bindingTestStream) SetDeadline(deadline time.Time) error {
	stream.deadlines = append(stream.deadlines, deadline)
	if len(stream.deadlines) == stream.failDeadline {
		return errors.New("deadline failure")
	}
	return nil
}

func TestLinkBindingPreservesProxyAndForwardResults(t *testing.T) {
	rejection := protocol.LinkErrorLocalDialFailed
	for _, test := range []struct {
		name           string
		message        protocol.MessageType
		result         protocol.BindResult
		empty          bool
		failDeadline   int
		proxyFailure   protocol.LinkErrorCode
		forwardFailure protocol.LinkErrorCode
		clearsDeadline bool
	}{
		{name: "accepted", result: protocol.BindResult{LinkID: "link", Status: protocol.LinkStatusAccepted}, clearsDeadline: true},
		{name: "wrong message", message: protocol.MessagePong, proxyFailure: protocol.LinkErrorInvalidBinding, forwardFailure: protocol.LinkErrorTransportFailed},
		{name: "read failure", empty: true, proxyFailure: protocol.LinkErrorTransportFailed, forwardFailure: protocol.LinkErrorTransportFailed},
		{name: "wrong link", result: protocol.BindResult{LinkID: "other", Status: protocol.LinkStatusAccepted}, proxyFailure: protocol.LinkErrorInvalidBinding, forwardFailure: protocol.LinkErrorInvalidBinding},
		{name: "rejected without code", result: protocol.BindResult{LinkID: "link"}, proxyFailure: protocol.LinkErrorInvalidBinding, forwardFailure: protocol.LinkErrorInvalidBinding},
		{name: "rejected with code", result: protocol.BindResult{LinkID: "link", Error: &rejection}, proxyFailure: rejection, forwardFailure: rejection},
		{name: "set deadline failure", failDeadline: 1, proxyFailure: protocol.LinkErrorTransportFailed, forwardFailure: protocol.LinkErrorTransportFailed},
		{name: "clear deadline failure", result: protocol.BindResult{LinkID: "link", Status: protocol.LinkStatusAccepted}, failDeadline: 2, proxyFailure: protocol.LinkErrorTransportFailed, forwardFailure: protocol.LinkErrorTransportFailed, clearsDeadline: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, forward := range []bool{false, true} {
				var response bytes.Buffer
				message := test.message
				if message == "" {
					message = protocol.MessageBindResult
				}
				if !test.empty {
					if err := protocol.WriteControl(&response, message, test.result); err != nil {
						t.Fatal(err)
					}
				}
				stream := &bindingTestStream{response: bytes.NewReader(response.Bytes()), failDeadline: test.failDeadline}
				expected := test.proxyFailure
				var failure protocol.LinkErrorCode
				if forward {
					expected = test.forwardFailure
					failure = (&forwardManager{}).bindForwardStream(stream, protocol.ForwardLinkOffer{LinkID: "link"})
				} else {
					failure = (&linkManager{}).bindDataStream(stream, protocol.OpenLink{LinkID: "link"})
				}
				if failure != expected {
					t.Fatalf("forward=%v: failure=%q, want %q", forward, failure, expected)
				}
				count := 1
				if test.clearsDeadline {
					count = 2
				}
				if len(stream.deadlines) != count || stream.deadlines[0].IsZero() {
					t.Fatalf("unexpected deadlines: %v", stream.deadlines)
				}
				if test.clearsDeadline && !stream.deadlines[1].IsZero() {
					t.Fatal("accepted binding retained deadline")
				}
			}
		})
	}
}
