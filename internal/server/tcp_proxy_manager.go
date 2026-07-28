package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/acexy/portway/internal/consts"
	"github.com/acexy/portway/internal/logging"
	"github.com/acexy/portway/internal/protocol"
	proxytcp "github.com/acexy/portway/internal/proxy/tcp"
)

var tcpProxyNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

type tcpProxyManager struct {
	logger              *logging.Logger
	proxyBindIP         string
	context             context.Context
	mutex               sync.Mutex
	registrationMutex   sync.Mutex
	clients             map[string]*clientTCPProxyState
	pendingLinks        map[string]*pendingTCPLink
	activeLinks         map[string]*activeTCPLink
	listenerWaitGroup   sync.WaitGroup
	closed              bool
}

type clientTCPProxyState struct {
	sessionID       string
	active          bool
	writer          *controlWriter
	revision        uint64
	fingerprint     [sha256.Size]byte
	lastRequestID   string
	lastResult      protocol.SyncResult
	proxies         map[string]*tcpProxyRuntime
}

type tcpProxyRuntime struct {
	manager     *tcpProxyManager
	clientID    string
	declaration protocol.ProxyDeclaration
	listener    net.Listener
	closeOnce   sync.Once
	startOnce   sync.Once
}

type pendingTCPLink struct {
	linkID       string
	clientID     string
	sessionID    string
	proxyName    string
	ticketDigest [sha256.Size]byte
	visitor      net.Conn
	timer        *time.Timer
}

type activeTCPLink struct {
	linkID    string
	clientID  string
	sessionID string
	proxyName string
	visitor   net.Conn
	data      net.Conn
}

func newTCPProxyManager(
	ctx context.Context,
	logger *logging.Logger,
	proxyBindIP string,
) *tcpProxyManager {
	return &tcpProxyManager{
		logger:        logger,
		proxyBindIP:   proxyBindIP,
		context:       ctx,
		clients:       make(map[string]*clientTCPProxyState),
		pendingLinks:  make(map[string]*pendingTCPLink),
		activeLinks:   make(map[string]*activeTCPLink),
	}
}

func (manager *tcpProxyManager) attach(
	clientID string,
	sessionID string,
	writer *controlWriter,
) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	state, exists := manager.clients[clientID]
	if !exists {
		state = &clientTCPProxyState{
			proxies: make(map[string]*tcpProxyRuntime),
		}
		manager.clients[clientID] = state
	}
	state.sessionID = sessionID
	state.active = false
	state.writer = writer
	state.revision = 0
	state.fingerprint = [sha256.Size]byte{}
	state.lastRequestID = ""
	state.lastResult = protocol.SyncResult{}
}

func (manager *tcpProxyManager) syncProxies(
	clientID string,
	sessionID string,
	requestID string,
	request protocol.SyncProxies,
) protocol.SyncResult {
	manager.registrationMutex.Lock()
	defer manager.registrationMutex.Unlock()

	manager.mutex.Lock()
	if manager.closed {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorSessionInactive,
			"",
			"TCP proxy manager is closed",
		)
	}
	manager.mutex.Unlock()

	if requestID == "" {
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorInvalidRequest,
			"",
			"request ID is required",
		)
	}
	fingerprintBytes, err := json.Marshal(request.Proxies)
	if err != nil {
		return rejectedSyncResult(request.Revision, protocol.ProxyErrorInvalidRequest, "", "encode proxy declaration")
	}
	fingerprint := sha256.Sum256(fingerprintBytes)

	manager.mutex.Lock()
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorSessionInactive,
			"",
			"client session is not active",
		)
	}
	if requestID == state.lastRequestID {
		result := state.lastResult
		manager.mutex.Unlock()
		return result
	}
	if request.Revision == 0 || request.Revision < state.revision {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorInvalidRequest,
			"",
			"proxy revision is stale",
		)
	}
	if request.Revision == state.revision {
		if subtle.ConstantTimeCompare(fingerprint[:], state.fingerprint[:]) == 1 {
			result := state.lastResult
			manager.mutex.Unlock()
			return result
		}
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorInvalidRequest,
			"",
			"proxy revision payload changed",
		)
	}
	if len(request.Proxies) > consts.ServerMaxTCPProxiesPerClient {
		manager.mutex.Unlock()
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorCapacityExceeded,
			"",
			"TCP proxy limit exceeded",
		)
	}
	existingProxies := make(map[string]*tcpProxyRuntime, len(state.proxies))
	for name, proxyRuntime := range state.proxies {
		existingProxies[name] = proxyRuntime
	}
	manager.mutex.Unlock()

	declarationsByName := make(map[string]protocol.ProxyDeclaration, len(request.Proxies))
	for _, declaration := range request.Proxies {
		if !tcpProxyNamePattern.MatchString(declaration.Name) ||
			declaration.Type != protocol.ProxyTypeTCP ||
			declaration.RemotePort == 0 {
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorInvalidProxy,
				declaration.Name,
				"invalid TCP proxy declaration",
			)
		}
		if _, duplicate := declarationsByName[declaration.Name]; duplicate {
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorInvalidProxy,
				declaration.Name,
				"duplicate proxy name",
			)
		}
		declarationsByName[declaration.Name] = declaration
	}

	nextProxies := make(map[string]*tcpProxyRuntime, len(request.Proxies))
	newProxies := make([]*tcpProxyRuntime, 0)
	results := make([]protocol.ProxyResult, 0, len(request.Proxies))
	for _, declaration := range request.Proxies {
		if existing, ok := existingProxies[declaration.Name]; ok &&
			existing.declaration == declaration {
			nextProxies[declaration.Name] = existing
			results = append(results, protocol.ProxyResult{
				Name:       declaration.Name,
				Status:     protocol.ProxyStatusUnchanged,
				RemotePort: declaration.RemotePort,
			})
			continue
		}

		listenAddress := net.JoinHostPort(manager.proxyBindIP, strconv.Itoa(int(declaration.RemotePort)))
		listener, err := (&net.ListenConfig{}).Listen(manager.context, "tcp", listenAddress)
		if err != nil {
			for _, newProxy := range newProxies {
				newProxy.close()
			}
			return rejectedSyncResult(
				request.Revision,
				protocol.ProxyErrorPortConflict,
				declaration.Name,
				"remote port is unavailable",
			)
		}
		proxyRuntime := &tcpProxyRuntime{
			manager:     manager,
			clientID:    clientID,
			declaration: declaration,
			listener:    listener,
		}
		nextProxies[declaration.Name] = proxyRuntime
		newProxies = append(newProxies, proxyRuntime)
		results = append(results, protocol.ProxyResult{
			Name:       declaration.Name,
			Status:     protocol.ProxyStatusActive,
			RemotePort: declaration.RemotePort,
		})
	}

	result := protocol.SyncResult{
		Revision: request.Revision,
		Status:   protocol.ProxySyncStatusApplied,
		Proxies:  results,
	}
	manager.mutex.Lock()
	state, exists = manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		for _, newProxy := range newProxies {
			newProxy.close()
		}
		return rejectedSyncResult(
			request.Revision,
			protocol.ProxyErrorSessionInactive,
			"",
			"client session changed during registration",
		)
	}
	state.proxies = nextProxies
	state.revision = request.Revision
	state.fingerprint = fingerprint
	state.lastRequestID = requestID
	state.lastResult = result
	manager.mutex.Unlock()

	for name, existing := range existingProxies {
		if nextProxies[name] != existing {
			existing.close()
		}
	}
	return result
}

func (manager *tcpProxyManager) activate(clientID string, sessionID string) {
	manager.mutex.Lock()
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		return
	}
	state.active = true
	proxies := make([]*tcpProxyRuntime, 0, len(state.proxies))
	for _, proxyRuntime := range state.proxies {
		proxies = append(proxies, proxyRuntime)
	}
	manager.mutex.Unlock()

	for _, proxyRuntime := range proxies {
		proxyRuntime.start()
	}
}

func (manager *tcpProxyManager) suspend(clientID string, sessionID string) {
	manager.mutex.Lock()
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		return
	}
	state.active = false
	state.writer = nil
	pending := manager.removePendingLocked(clientID, sessionID, "")
	active := manager.removeActiveLocked(clientID, sessionID, "")
	manager.mutex.Unlock()

	closePendingLinks(pending)
	closeActiveLinks(active)
}

func (manager *tcpProxyManager) remove(clientID string, sessionID string) {
	manager.mutex.Lock()
	state, exists := manager.clients[clientID]
	if !exists || state.sessionID != sessionID {
		manager.mutex.Unlock()
		return
	}
	delete(manager.clients, clientID)
	proxies := make([]*tcpProxyRuntime, 0, len(state.proxies))
	for _, proxyRuntime := range state.proxies {
		proxies = append(proxies, proxyRuntime)
	}
	pending := manager.removePendingLocked(clientID, sessionID, "")
	active := manager.removeActiveLocked(clientID, sessionID, "")
	manager.mutex.Unlock()

	for _, proxyRuntime := range proxies {
		proxyRuntime.close()
	}
	closePendingLinks(pending)
	closeActiveLinks(active)
}

func (manager *tcpProxyManager) reportLinkFailure(
	clientID string,
	sessionID string,
	failure protocol.LinkFailed,
) {
	manager.mutex.Lock()
	pending, exists := manager.pendingLinks[failure.LinkID]
	if !exists || pending.clientID != clientID || pending.sessionID != sessionID {
		manager.mutex.Unlock()
		return
	}
	delete(manager.pendingLinks, failure.LinkID)
	manager.mutex.Unlock()

	pending.timer.Stop()
	pending.visitor.Close()
}

func (manager *tcpProxyManager) bindDataConnection(
	binding protocol.BindLink,
	dataConnection net.Conn,
) (*activeTCPLink, protocol.LinkErrorCode) {
	ticketBytes, err := base64.RawURLEncoding.DecodeString(binding.Ticket)
	if err != nil {
		return nil, protocol.LinkErrorInvalidBinding
	}
	ticketDigest := sha256.Sum256(ticketBytes)

	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	pending, exists := manager.pendingLinks[binding.LinkID]
	if !exists {
		return nil, protocol.LinkErrorExpired
	}
	state, active := manager.clients[binding.ClientID]
	if !active ||
		!state.active ||
		state.sessionID != binding.SessionID ||
		pending.clientID != binding.ClientID ||
		pending.sessionID != binding.SessionID ||
		subtle.ConstantTimeCompare(ticketDigest[:], pending.ticketDigest[:]) != 1 {
		return nil, protocol.LinkErrorInvalidBinding
	}
	if manager.activeLinkLimitReachedLocked(pending.clientID, pending.proxyName) {
		return nil, protocol.LinkErrorCancelled
	}

	delete(manager.pendingLinks, binding.LinkID)
	pending.timer.Stop()
	link := &activeTCPLink{
		linkID:    pending.linkID,
		clientID:  pending.clientID,
		sessionID: pending.sessionID,
		proxyName: pending.proxyName,
		visitor:   pending.visitor,
		data:      dataConnection,
	}
	manager.activeLinks[link.linkID] = link
	return link, ""
}

func (manager *tcpProxyManager) finishActiveLink(linkID string) {
	manager.mutex.Lock()
	delete(manager.activeLinks, linkID)
	manager.mutex.Unlock()
}

func (manager *tcpProxyManager) close() {
	manager.registrationMutex.Lock()
	defer manager.registrationMutex.Unlock()

	manager.mutex.Lock()
	manager.closed = true
	proxies := make([]*tcpProxyRuntime, 0)
	for _, state := range manager.clients {
		for _, proxyRuntime := range state.proxies {
			proxies = append(proxies, proxyRuntime)
		}
	}
	pending := manager.removePendingLocked("", "", "")
	active := manager.removeActiveLocked("", "", "")
	manager.clients = make(map[string]*clientTCPProxyState)
	manager.mutex.Unlock()

	for _, proxyRuntime := range proxies {
		proxyRuntime.close()
	}
	closePendingLinks(pending)
	closeActiveLinks(active)
	manager.listenerWaitGroup.Wait()
}

func (runtime *tcpProxyRuntime) start() {
	runtime.startOnce.Do(func() {
		runtime.manager.listenerWaitGroup.Add(1)
		go func() {
			defer runtime.manager.listenerWaitGroup.Done()
			for {
				visitor, err := runtime.listener.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) || runtime.manager.context.Err() != nil {
						return
					}
					runtime.manager.logger.Error("TCP proxy listener failed", err)
					return
				}
				runtime.manager.openVisitor(runtime, visitor)
			}
		}()
	})
}

func (runtime *tcpProxyRuntime) close() {
	runtime.closeOnce.Do(func() {
		runtime.listener.Close()
	})
}

func (manager *tcpProxyManager) openVisitor(runtime *tcpProxyRuntime, visitor net.Conn) {
	linkID, ticket, ticketDigest, err := newLinkCredentials()
	if err != nil {
		visitor.Close()
		manager.logger.Error("failed to generate TCP link credentials", err)
		return
	}

	manager.mutex.Lock()
	state, exists := manager.clients[runtime.clientID]
	if manager.closed ||
		!exists ||
		!state.active ||
		state.proxies[runtime.declaration.Name] != runtime ||
		state.writer == nil ||
		manager.pendingLinkLimitReachedLocked(runtime.clientID, runtime.declaration.Name) {
		manager.mutex.Unlock()
		visitor.Close()
		return
	}
	pending := &pendingTCPLink{
		linkID:       linkID,
		clientID:     runtime.clientID,
		sessionID:    state.sessionID,
		proxyName:    runtime.declaration.Name,
		ticketDigest: ticketDigest,
		visitor:      visitor,
	}
	manager.pendingLinks[linkID] = pending
	pending.timer = time.AfterFunc(consts.TCPPendingLinkTimeout, func() {
		manager.expirePendingLink(linkID)
	})
	writer := state.writer
	sessionID := state.sessionID
	manager.mutex.Unlock()

	err = writer.write(protocol.MessageOpenLink, protocol.OpenLink{
		LinkID:          linkID,
		ProxyName:       runtime.declaration.Name,
		Ticket:          ticket,
		ExpiresAtUnixMS: time.Now().Add(consts.TCPPendingLinkTimeout).UnixMilli(),
	})
	if err != nil {
		manager.cancelPendingLink(linkID, false)
		return
	}
	manager.logger.WithFields(map[string]any{
		"client_id":  runtime.clientID,
		"session_id": sessionID,
		"proxy_name": runtime.declaration.Name,
		"link_id":    linkID,
	}).Trace("open link sent")
}

func (manager *tcpProxyManager) expirePendingLink(linkID string) {
	manager.cancelPendingLink(linkID, true)
}

func (manager *tcpProxyManager) cancelPendingLink(linkID string, notifyClient bool) {
	manager.mutex.Lock()
	pending, exists := manager.pendingLinks[linkID]
	if !exists {
		manager.mutex.Unlock()
		return
	}
	delete(manager.pendingLinks, linkID)
	state := manager.clients[pending.clientID]
	var writer *controlWriter
	if state != nil && state.active && state.sessionID == pending.sessionID {
		writer = state.writer
	}
	manager.mutex.Unlock()

	pending.timer.Stop()
	pending.visitor.Close()
	if notifyClient && writer != nil {
		_ = writer.write(protocol.MessageCancelLink, protocol.CancelLink{
			LinkID: linkID,
			Reason: "link_expired",
		})
	}
}

func (manager *tcpProxyManager) pendingLinkLimitReachedLocked(
	clientID string,
	proxyName string,
) bool {
	if len(manager.pendingLinks) >= consts.ServerMaxTCPPendingLinks {
		return true
	}
	clientCount := 0
	proxyCount := 0
	for _, pending := range manager.pendingLinks {
		if pending.clientID == clientID {
			clientCount++
			if pending.proxyName == proxyName {
				proxyCount++
			}
		}
	}
	return clientCount >= consts.ServerMaxTCPPendingLinksPerClient ||
		proxyCount >= consts.ServerMaxTCPPendingLinksPerProxy
}

func (manager *tcpProxyManager) activeLinkLimitReachedLocked(
	clientID string,
	proxyName string,
) bool {
	if len(manager.activeLinks) >= consts.ServerMaxTCPActiveLinks {
		return true
	}
	clientCount := 0
	proxyCount := 0
	for _, active := range manager.activeLinks {
		if active.clientID == clientID {
			clientCount++
			if active.proxyName == proxyName {
				proxyCount++
			}
		}
	}
	return clientCount >= consts.ServerMaxTCPActiveLinksPerClient ||
		proxyCount >= consts.ServerMaxTCPActiveLinksPerProxy
}

func (manager *tcpProxyManager) removePendingLocked(
	clientID string,
	sessionID string,
	proxyName string,
) []*pendingTCPLink {
	removed := make([]*pendingTCPLink, 0)
	for linkID, pending := range manager.pendingLinks {
		if (clientID == "" || pending.clientID == clientID) &&
			(sessionID == "" || pending.sessionID == sessionID) &&
			(proxyName == "" || pending.proxyName == proxyName) {
			delete(manager.pendingLinks, linkID)
			removed = append(removed, pending)
		}
	}
	return removed
}

func (manager *tcpProxyManager) removeActiveLocked(
	clientID string,
	sessionID string,
	proxyName string,
) []*activeTCPLink {
	removed := make([]*activeTCPLink, 0)
	for linkID, active := range manager.activeLinks {
		if (clientID == "" || active.clientID == clientID) &&
			(sessionID == "" || active.sessionID == sessionID) &&
			(proxyName == "" || active.proxyName == proxyName) {
			delete(manager.activeLinks, linkID)
			removed = append(removed, active)
		}
	}
	return removed
}

func (manager *tcpProxyManager) handleDataStream(
	ctx context.Context,
	connection net.Conn,
	binding protocol.BindLink,
	logger *logging.Logger,
) error {
	link, linkError := manager.bindDataConnection(binding, connection)
	if linkError != "" {
		_ = protocol.WriteControl(connection, protocol.MessageBindResult, protocol.BindResult{
			LinkID: binding.LinkID,
			Status: protocol.LinkStatusRejected,
			Error:  &linkError,
		})
		return fmt.Errorf("bind TCP data link: %s", linkError)
	}
	defer manager.finishActiveLink(link.linkID)

	if err := protocol.WriteControl(connection, protocol.MessageBindResult, protocol.BindResult{
		LinkID: link.linkID,
		Status: protocol.LinkStatusAccepted,
	}); err != nil {
		link.visitor.Close()
		return err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		link.visitor.Close()
		return err
	}
	logger.Trace("TCP link streaming started")
	err := proxytcp.Forward(ctx, link.visitor, connection)
	logger.Trace("TCP link streaming stopped")
	return err
}

func newLinkCredentials() (
	linkID string,
	ticket string,
	ticketDigest [sha256.Size]byte,
	err error,
) {
	linkBytes := make([]byte, 16)
	if _, err = rand.Read(linkBytes); err != nil {
		return "", "", ticketDigest, err
	}
	ticketBytes := make([]byte, 32)
	if _, err = rand.Read(ticketBytes); err != nil {
		return "", "", ticketDigest, err
	}
	return base64.RawURLEncoding.EncodeToString(linkBytes),
		base64.RawURLEncoding.EncodeToString(ticketBytes),
		sha256.Sum256(ticketBytes),
		nil
}

func rejectedSyncResult(
	revision uint64,
	code protocol.ProxyErrorCode,
	proxyName string,
	message string,
) protocol.SyncResult {
	return protocol.SyncResult{
		Revision: revision,
		Status:   protocol.ProxySyncStatusRejected,
		Proxies:  []protocol.ProxyResult{},
		Error: &protocol.ProxyError{
			Code:      code,
			Message:   message,
			ProxyName: proxyName,
			Retryable: false,
		},
	}
}

func closePendingLinks(links []*pendingTCPLink) {
	for _, link := range links {
		if link.timer != nil {
			link.timer.Stop()
		}
		link.visitor.Close()
	}
}

func closeActiveLinks(links []*activeTCPLink) {
	for _, link := range links {
		link.visitor.Close()
		link.data.Close()
	}
}
