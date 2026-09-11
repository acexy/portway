package vnet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/acexy/portway/internal/authentication"
	"github.com/acexy/portway/internal/protocol"
)

const vnetChannelTicketBytes = 32

// PoolSpec binds a complete channel pool to one authenticated transport generation.
type PoolSpec struct {
	ClientID            string
	SessionID           string
	TransportGeneration uint64
	VirtualIP           string
	PoolGeneration      uint64
	ChannelCount        uint8
	MTU                 uint16
	WriteTimeout        time.Duration
	Authentication      authentication.Context
}

type pendingChannel struct {
	ticketDigest [sha256.Size]byte
	connection   net.Conn
}

type pendingPool struct {
	spec      PoolSpec
	channels  []pendingChannel
	expiresAt time.Time
	timer     *time.Timer
	done      chan struct{}
	closeOnce sync.Once
}

// Pool is one atomically activated set of VNet packet channels.
type Pool struct {
	spec       PoolSpec
	channels   []net.Conn
	writeMutex []sync.Mutex
	done       chan struct{}
	closeOnce  sync.Once
}

// PoolBroker owns pending and active VNet channel pool generations.
type PoolBroker struct {
	mutex   sync.Mutex
	pending map[string]*pendingPool
	active  map[string]*Pool
	closed  bool
}

// NewPoolBroker creates an empty VNet pool broker.
func NewPoolBroker() *PoolBroker {
	return &PoolBroker{
		pending: make(map[string]*pendingPool),
		active:  make(map[string]*Pool),
	}
}

// Prepare creates one ticket per channel index and replaces older pending state.
func (broker *PoolBroker) Prepare(spec PoolSpec, lifetime time.Duration) ([]protocol.OpenVNetChannel, error) {
	if spec.ClientID == "" || spec.SessionID == "" || spec.VirtualIP == "" ||
		spec.PoolGeneration == 0 || spec.ChannelCount < 1 || spec.ChannelCount > 8 || spec.MTU < 68 ||
		spec.WriteTimeout <= 0 {
		return nil, errors.New("invalid VNet pool specification")
	}
	if lifetime <= 0 {
		return nil, errors.New("VNet pool ticket lifetime must be positive")
	}
	expiresAt := time.Now().Add(lifetime)
	pending := &pendingPool{
		spec:      spec,
		channels:  make([]pendingChannel, int(spec.ChannelCount)),
		expiresAt: expiresAt,
		done:      make(chan struct{}),
	}
	offers := make([]protocol.OpenVNetChannel, int(spec.ChannelCount))
	for index := range pending.channels {
		ticket := make([]byte, vnetChannelTicketBytes)
		if _, err := rand.Read(ticket); err != nil {
			closePendingPool(pending)
			return nil, fmt.Errorf("generate VNet channel ticket: %w", err)
		}
		pending.channels[index].ticketDigest = sha256.Sum256(ticket)
		offers[index] = protocol.OpenVNetChannel{
			PoolGeneration:  spec.PoolGeneration,
			ChannelIndex:    uint8(index),
			ChannelCount:    spec.ChannelCount,
			Ticket:          base64.RawURLEncoding.EncodeToString(ticket),
			ExpiresAtUnixMS: expiresAt.UnixMilli(),
		}
	}
	broker.mutex.Lock()
	if broker.closed {
		broker.mutex.Unlock()
		closePendingPool(pending)
		return nil, errors.New("VNet pool broker is closed")
	}
	previous := broker.pending[spec.ClientID]
	broker.pending[spec.ClientID] = pending
	pending.timer = time.AfterFunc(lifetime, func() { broker.expire(spec.ClientID, spec.PoolGeneration) })
	broker.mutex.Unlock()
	closePendingPool(previous)
	return offers, nil
}

// Bind validates one channel and blocks while the broker owns its connection.
func (broker *PoolBroker) Bind(
	ctx context.Context,
	connection net.Conn,
	binding protocol.BindVNetChannel,
	authenticationContext authentication.Context,
	onBound func(),
	onActive func(*Pool),
) error {
	ticket, err := base64.RawURLEncoding.DecodeString(binding.Ticket)
	if err != nil || len(ticket) != vnetChannelTicketBytes {
		return errors.New("invalid VNet channel ticket")
	}
	digest := sha256.Sum256(ticket)
	broker.mutex.Lock()
	if broker.closed {
		broker.mutex.Unlock()
		return errors.New("VNet pool broker is closed")
	}
	pending := broker.pending[binding.ClientID]
	if pending == nil || !time.Now().Before(pending.expiresAt) ||
		!bindingMatchesPool(binding, pending.spec, authenticationContext) ||
		int(binding.ChannelIndex) >= len(pending.channels) {
		broker.mutex.Unlock()
		return errors.New("invalid VNet channel binding")
	}
	channel := &pending.channels[binding.ChannelIndex]
	if channel.connection != nil || subtle.ConstantTimeCompare(digest[:], channel.ticketDigest[:]) != 1 {
		broker.mutex.Unlock()
		return errors.New("invalid VNet channel binding")
	}
	channel.connection = connection
	complete := true
	for index := range pending.channels {
		complete = complete && pending.channels[index].connection != nil
	}
	var pool *Pool
	if complete {
		delete(broker.pending, binding.ClientID)
		pending.timer.Stop()
		pool = activatePendingPool(pending)
		previous := broker.active[binding.ClientID]
		broker.active[binding.ClientID] = pool
		if previous != nil {
			previous.Close()
		}
	}
	done := pending.done
	broker.mutex.Unlock()
	if onBound != nil {
		onBound()
	}
	if pool != nil && onActive != nil {
		onActive(pool)
	}
	select {
	case <-ctx.Done():
		broker.Remove(binding.ClientID, binding.SessionID)
		return ctx.Err()
	case <-done:
		return nil
	}
}

// Close releases every pending and active pool.
func (broker *PoolBroker) Close() {
	broker.mutex.Lock()
	if broker.closed {
		broker.mutex.Unlock()
		return
	}
	broker.closed = true
	pending := make([]*pendingPool, 0, len(broker.pending))
	for _, pool := range broker.pending {
		pending = append(pending, pool)
	}
	active := make([]*Pool, 0, len(broker.active))
	for _, pool := range broker.active {
		active = append(active, pool)
	}
	broker.pending = make(map[string]*pendingPool)
	broker.active = make(map[string]*Pool)
	broker.mutex.Unlock()
	for _, pool := range pending {
		closePendingPool(pool)
	}
	for _, pool := range active {
		pool.Close()
	}
}

// Active returns the current pool for one client.
func (broker *PoolBroker) Active(clientID string) (*Pool, bool) {
	broker.mutex.Lock()
	defer broker.mutex.Unlock()
	pool, exists := broker.active[clientID]
	return pool, exists
}

// Remove closes pending and active resources owned by one exact session.
func (broker *PoolBroker) Remove(clientID string, sessionID string) {
	broker.mutex.Lock()
	pending := broker.pending[clientID]
	if pending != nil && pending.spec.SessionID == sessionID {
		delete(broker.pending, clientID)
	} else {
		pending = nil
	}
	pool := broker.active[clientID]
	if pool != nil && pool.spec.SessionID == sessionID {
		delete(broker.active, clientID)
	} else {
		pool = nil
	}
	broker.mutex.Unlock()
	closePendingPool(pending)
	if pool != nil {
		pool.Close()
	}
}

func (broker *PoolBroker) expire(clientID string, generation uint64) {
	broker.mutex.Lock()
	pending := broker.pending[clientID]
	if pending != nil && pending.spec.PoolGeneration == generation {
		delete(broker.pending, clientID)
	} else {
		pending = nil
	}
	broker.mutex.Unlock()
	closePendingPool(pending)
}

// Send writes one packet to its stable channel index.
func (pool *Pool) Send(packet []byte, index uint8) error {
	if int(index) >= len(pool.channels) {
		return errors.New("VNet channel index is out of range")
	}
	pool.writeMutex[index].Lock()
	defer pool.writeMutex[index].Unlock()
	connection := pool.channels[index]
	if err := connection.SetWriteDeadline(time.Now().Add(pool.spec.WriteTimeout)); err != nil {
		return err
	}
	err := WritePacket(connection, packet, pool.spec.MTU)
	clearError := connection.SetWriteDeadline(time.Time{})
	return errors.Join(err, clearError)
}

// RunReaders reads every channel until one fails or the pool is closed.
func (pool *Pool) RunReaders(handler func([]byte) error) error {
	errorsChannel := make(chan error, len(pool.channels))
	for _, connection := range pool.channels {
		go func(channel net.Conn) {
			for {
				packet, err := ReadPacket(channel, pool.spec.MTU)
				if err == nil {
					err = handler(packet)
				}
				if err != nil {
					errorsChannel <- err
					return
				}
			}
		}(connection)
	}
	err := <-errorsChannel
	pool.Close()
	return err
}

// Close closes every channel in the pool exactly once.
func (pool *Pool) Close() error {
	var result error
	pool.closeOnce.Do(func() {
		close(pool.done)
		for _, connection := range pool.channels {
			result = errors.Join(result, connection.Close())
		}
	})
	return result
}

func bindingMatchesPool(
	binding protocol.BindVNetChannel,
	spec PoolSpec,
	authenticationContext authentication.Context,
) bool {
	return binding.ClientID == spec.ClientID && binding.SessionID == spec.SessionID &&
		binding.TransportGeneration == spec.TransportGeneration && binding.VirtualIP == spec.VirtualIP &&
		binding.PoolGeneration == spec.PoolGeneration && binding.ChannelCount == spec.ChannelCount &&
		authenticationContext == spec.Authentication
}

func activatePendingPool(pending *pendingPool) *Pool {
	channels := make([]net.Conn, len(pending.channels))
	for index := range pending.channels {
		channels[index] = pending.channels[index].connection
	}
	return &Pool{
		spec:       pending.spec,
		channels:   channels,
		writeMutex: make([]sync.Mutex, len(channels)),
		done:       pending.done,
	}
}

func closePendingPool(pending *pendingPool) {
	if pending == nil {
		return
	}
	pending.closeOnce.Do(func() {
		if pending.timer != nil {
			pending.timer.Stop()
		}
		close(pending.done)
		for _, channel := range pending.channels {
			if channel.connection != nil {
				channel.connection.Close()
			}
		}
	})
}
