package quic

import (
	"time"

	quicgo "github.com/quic-go/quic-go"
)

const (
	alpn                       = "portway"
	authenticationMagic        = "PWQA"
	authenticationSelectorSize = 32
	authenticationNonceSize    = 32
	authenticationProofSize    = 32
	authenticationTimeout      = 5 * time.Second

	maxIncomingStreams     = 512
	maxStreamReceiveWindow = 6 * 1024 * 1024
	maxConnectionWindow    = 32 * 1024 * 1024
	maxIdleTimeout         = 90 * time.Second
	keepAlivePeriod        = 20 * time.Second
)

const (
	applicationErrorShutdown quicgo.ApplicationErrorCode = 0x01
	applicationErrorAuth     quicgo.ApplicationErrorCode = 0x02
	applicationErrorProtocol quicgo.ApplicationErrorCode = 0x03
	streamErrorClosed        quicgo.StreamErrorCode      = 0x10
)

func defaultQUICConfig() *quicgo.Config {
	return &quicgo.Config{
		HandshakeIdleTimeout:       authenticationTimeout,
		MaxIdleTimeout:             maxIdleTimeout,
		MaxStreamReceiveWindow:     maxStreamReceiveWindow,
		MaxConnectionReceiveWindow: maxConnectionWindow,
		MaxIncomingStreams:         maxIncomingStreams,
		MaxIncomingUniStreams:      -1,
		KeepAlivePeriod:            keepAlivePeriod,
		Allow0RTT:                  false,
		EnableDatagrams:            false,
	}
}
