package quic

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"time"

	"github.com/acexy/golang-toolkit/util/coll"
	quicgo "github.com/quic-go/quic-go"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/transport"
)

func authenticateClient(
	ctx context.Context,
	stream *quicgo.Stream,
	token string,
) error {
	if token == "" {
		return transport.ErrAuthentication
	}
	stopContextCancel := cancelStreamOnContext(ctx, stream)
	defer stopContextCancel()
	if err := stream.SetDeadline(authenticationDeadline(ctx)); err != nil {
		return fmt.Errorf("set QUIC authentication deadline: %w", err)
	}
	defer stream.SetDeadline(time.Time{})

	clientNonce := make([]byte, authenticationNonceSize)
	if _, err := rand.Read(clientNonce); err != nil {
		return fmt.Errorf("generate QUIC client nonce: %w", err)
	}
	selector := authentication.Selector(token)
	if err := writeFull(
		stream,
		joinBytes([]byte(authenticationMagic), selector[:], clientNonce),
	); err != nil {
		return fmt.Errorf("write QUIC client nonce: %w", err)
	}

	serverResponse := make([]byte, len(authenticationMagic)+authenticationNonceSize+authenticationProofSize)
	if _, err := io.ReadFull(stream, serverResponse); err != nil {
		return fmt.Errorf("read QUIC server proof: %w", err)
	}
	if string(serverResponse[:len(authenticationMagic)]) != authenticationMagic {
		return transport.ErrProtocol
	}
	serverNonce := serverResponse[len(authenticationMagic) : len(authenticationMagic)+authenticationNonceSize]
	serverProof := serverResponse[len(authenticationMagic)+authenticationNonceSize:]
	transcript := authenticationTranscript(selector[:], clientNonce, serverNonce)
	expectedProof := authenticationProof(token, "server", transcript)
	if subtle.ConstantTimeCompare(serverProof, expectedProof) != 1 {
		return transport.ErrAuthentication
	}
	if err := writeFull(stream, authenticationProof(token, "client", transcript)); err != nil {
		return fmt.Errorf("write QUIC client proof: %w", err)
	}

	acknowledgement := make([]byte, len(authenticationMagic)+1)
	if _, err := io.ReadFull(stream, acknowledgement); err != nil {
		return fmt.Errorf("read QUIC authentication result: %w", err)
	}
	if string(acknowledgement[:len(authenticationMagic)]) != authenticationMagic ||
		acknowledgement[len(authenticationMagic)] != 1 {
		return transport.ErrAuthentication
	}
	return nil
}

func authenticateServer(
	ctx context.Context,
	stream *quicgo.Stream,
	credentials *authentication.Store,
) (authentication.Context, error) {
	if credentials == nil {
		return authentication.Context{}, transport.ErrAuthentication
	}
	stopContextCancel := cancelStreamOnContext(ctx, stream)
	defer stopContextCancel()
	if err := stream.SetDeadline(authenticationDeadline(ctx)); err != nil {
		return authentication.Context{}, fmt.Errorf("set QUIC authentication deadline: %w", err)
	}
	defer stream.SetDeadline(time.Time{})

	clientHello := make(
		[]byte,
		len(authenticationMagic)+authenticationSelectorSize+authenticationNonceSize,
	)
	if _, err := io.ReadFull(stream, clientHello); err != nil {
		return authentication.Context{}, fmt.Errorf("read QUIC client nonce: %w", err)
	}
	if string(clientHello[:len(authenticationMagic)]) != authenticationMagic {
		return authentication.Context{}, transport.ErrProtocol
	}
	selectorStart := len(authenticationMagic)
	selectorEnd := selectorStart + authenticationSelectorSize
	record, exists := credentials.Resolve(clientHello[selectorStart:selectorEnd])
	if !exists {
		// Continue with a fixed dummy key so unknown selectors and wrong Tokens
		// have the same externally observable proof exchange.
		record.Token = string(make([]byte, 32))
	}
	token := record.Token
	clientNonce := clientHello[selectorEnd:]
	serverNonce := make([]byte, authenticationNonceSize)
	if _, err := rand.Read(serverNonce); err != nil {
		return authentication.Context{}, fmt.Errorf("generate QUIC server nonce: %w", err)
	}
	transcript := authenticationTranscript(
		clientHello[selectorStart:selectorEnd],
		clientNonce,
		serverNonce,
	)
	serverResponse := joinBytes(
		[]byte(authenticationMagic),
		serverNonce,
		authenticationProof(token, "server", transcript),
	)
	if err := writeFull(stream, serverResponse); err != nil {
		return authentication.Context{}, fmt.Errorf("write QUIC server proof: %w", err)
	}

	clientProof := make([]byte, authenticationProofSize)
	if _, err := io.ReadFull(stream, clientProof); err != nil {
		return authentication.Context{}, fmt.Errorf("read QUIC client proof: %w", err)
	}
	expectedProof := authenticationProof(token, "client", transcript)
	proofValid := subtle.ConstantTimeCompare(clientProof, expectedProof) == 1
	if !exists || !proofValid {
		return authentication.Context{}, transport.ErrAuthentication
	}
	if err := writeFull(stream, joinBytes([]byte(authenticationMagic), []byte{1})); err != nil {
		return authentication.Context{}, fmt.Errorf("write QUIC authentication result: %w", err)
	}
	return record.Context, nil
}

func authenticationTranscript(
	selector []byte,
	clientNonce []byte,
	serverNonce []byte,
) []byte {
	return joinBytes([]byte(alpn), selector, clientNonce, serverNonce)
}

func authenticationProof(token string, direction string, transcript []byte) []byte {
	messageAuthenticationCode := hmac.New(sha256.New, []byte(token))
	messageAuthenticationCode.Write([]byte("portway-quic/" + direction))
	messageAuthenticationCode.Write(transcript)
	return messageAuthenticationCode.Sum(nil)
}

func authenticationDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(authenticationTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func cancelStreamOnContext(ctx context.Context, stream *quicgo.Stream) func() bool {
	return context.AfterFunc(ctx, func() {
		stream.CancelRead(streamErrorClosed)
		stream.CancelWrite(streamErrorClosed)
	})
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[written:]
	}
	return nil
}

func joinBytes(parts ...[]byte) []byte {
	return coll.SliceFlat(parts)
}
