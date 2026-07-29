// Package ipfilter provides server-wide source IP deny-list enforcement.
package ipfilter

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"

	"github.com/acexy/portway/internal/logging"
)

const (
	reloadInterval  = 3 * time.Second
	headerErrorLogInterval = time.Minute
	maxFileSize     = 4 * 1024 * 1024
	maxRuleCount    = 100000
	readLimit       = maxFileSize + 1
)

type ruleSnapshot struct {
	prefixes *bart.Lite
	digest [sha256.Size]byte
	count  int
}

type trackedSource struct {
	address netip.Addr
	close   func()
}

// Filter owns one immutable deny-list snapshot, its watcher, and active source
// registrations that must be closed when a new rule starts matching.
type Filter struct {
	logger       *logging.Logger
	path         string
	snapshot     atomic.Pointer[ruleSnapshot]
	mutex        sync.Mutex
	nextSourceID uint64
	sources      map[uint64]trackedSource
	lastError    string
	lastHeaderErrorLog atomic.Int64
	cancel       context.CancelFunc
	waitGroup    sync.WaitGroup
}

func (filter *Filter) logInvalidHTTPHeader(err error) {
	now := time.Now().UnixNano()
	previous := filter.lastHeaderErrorLog.Load()
	if previous != 0 &&
		time.Duration(now-previous) < headerErrorLogInterval {
		return
	}
	if !filter.lastHeaderErrorLog.CompareAndSwap(previous, now) {
		return
	}
	filter.logger.Error(
		"invalid HTTP client IP header; closing connection",
		err,
	)
}

// New validates the initial file before starting its context-owned watcher.
// An empty path creates an enabled no-op filter.
func New(
	ctx context.Context,
	logger *logging.Logger,
	path string,
) (*Filter, error) {
	filterContext, cancel := context.WithCancel(ctx)
	filter := &Filter{
		logger:  logger,
		path:    path,
		sources: make(map[uint64]trackedSource),
		cancel:  cancel,
	}
	filter.snapshot.Store(emptySnapshot())
	if path == "" {
		return filter, nil
	}
	snapshot, err := loadSnapshot(path)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("load source IP deny file %q: %w", path, err)
	}
	filter.snapshot.Store(snapshot)
	filter.logger.InfoWithField(
		"source IP deny list loaded",
		"rules",
		snapshot.count,
	)
	filter.waitGroup.Add(1)
	go filter.watch(filterContext)
	return filter, nil
}

// Close stops the watcher. Connection ownership remains with each listener.
func (filter *Filter) Close() {
	filter.cancel()
	filter.waitGroup.Wait()
}

// Enabled reports whether a deny-list file was configured.
func (filter *Filter) Enabled() bool {
	return filter != nil && filter.path != ""
}

// Denied reports whether a parsed source address matches the current snapshot.
func (filter *Filter) Denied(address netip.Addr) bool {
	if !address.IsValid() {
		return true
	}
	address = address.Unmap()
	return filter.snapshot.Load().prefixes.Contains(address)
}

// Register records a live connection source and returns an idempotent release
// function. A denied source is rejected without registration.
func (filter *Filter) Register(
	address netip.Addr,
	closeConnection func(),
) (release func(), allowed bool) {
	if !filter.Enabled() {
		return func() {}, true
	}
	if !address.IsValid() || closeConnection == nil {
		return func() {}, false
	}
	address = address.Unmap()
	filter.mutex.Lock()
	if filter.Denied(address) {
		filter.mutex.Unlock()
		filter.logger.TraceWithField(
			"source IP denied",
			"source_ip",
			address.String(),
		)
		return func() {}, false
	}
	filter.nextSourceID++
	sourceID := filter.nextSourceID
	filter.sources[sourceID] = trackedSource{
		address: address,
		close:   closeConnection,
	}
	filter.mutex.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			filter.mutex.Lock()
			delete(filter.sources, sourceID)
			filter.mutex.Unlock()
		})
	}, true
}

func (filter *Filter) watch(ctx context.Context) {
	defer filter.waitGroup.Done()
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			filter.reload()
		}
	}
}

func (filter *Filter) reload() {
	snapshot, err := loadSnapshot(filter.path)
	if err != nil {
		filter.logReloadError(err)
		return
	}
	current := filter.snapshot.Load()
	if current.digest == snapshot.digest {
		filter.clearReloadError()
		return
	}

	var closeConnections []func()
	filter.mutex.Lock()
	filter.snapshot.Store(snapshot)
	for _, source := range filter.sources {
		if snapshot.prefixes.Contains(source.address) {
			closeConnections = append(closeConnections, source.close)
		}
	}
	filter.lastError = ""
	filter.mutex.Unlock()

	for _, closeConnection := range closeConnections {
		closeConnection()
	}
	filter.logger.InfoWithField(
		"source IP deny list reloaded",
		"rules",
		snapshot.count,
	)
}

func (filter *Filter) logReloadError(err error) {
	message := err.Error()
	filter.mutex.Lock()
	if filter.lastError == message {
		filter.mutex.Unlock()
		return
	}
	filter.lastError = message
	filter.mutex.Unlock()
	filter.logger.Error("failed to reload source IP deny list; keeping previous rules", err)
}

func (filter *Filter) clearReloadError() {
	filter.mutex.Lock()
	filter.lastError = ""
	filter.mutex.Unlock()
}

func loadSnapshot(path string) (*ruleSnapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, readLimit))
	if err != nil {
		return nil, err
	}
	if len(content) > maxFileSize {
		return nil, fmt.Errorf("deny file exceeds %d bytes", maxFileSize)
	}

	prefixes := &bart.Lite{}
	seen := make(map[string]struct{})
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	for index, line := range lines {
		rule := strings.TrimSpace(line)
		if rule == "" || strings.HasPrefix(rule, "#") {
			continue
		}
		prefix, err := parseRule(rule)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", index+1, err)
		}
		normalized := prefix.String()
		if _, exists := seen[normalized]; exists {
			continue
		}
		if len(seen) >= maxRuleCount {
			return nil, fmt.Errorf("deny file exceeds %d rules", maxRuleCount)
		}
		seen[normalized] = struct{}{}
		prefixes.Insert(prefix)
	}
	return &ruleSnapshot{
		prefixes: prefixes,
		digest: sha256.Sum256(content),
		count:  len(seen),
	}, nil
}

func parseRule(rule string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(rule); err == nil {
		address := prefix.Addr()
		bits := prefix.Bits()
		if address.Is4In6() {
			if bits < 96 {
				return netip.Prefix{}, fmt.Errorf(
					"IPv4-mapped CIDR %q has an invalid prefix length",
					rule,
				)
			}
			address = address.Unmap()
			bits -= 96
		}
		return netip.PrefixFrom(address, bits).Masked(), nil
	}
	address, err := netip.ParseAddr(rule)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP or CIDR %q", rule)
	}
	address = address.Unmap()
	return netip.PrefixFrom(address, address.BitLen()), nil
}

func emptySnapshot() *ruleSnapshot {
	return &ruleSnapshot{prefixes: &bart.Lite{}}
}

// ParseRemoteAddress extracts and normalizes an IP from a socket address.
func ParseRemoteAddress(address net.Addr) (netip.Addr, error) {
	if address == nil {
		return netip.Addr{}, errors.New("remote address is unavailable")
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse remote address %q: %w", address, err)
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse remote IP %q: %w", host, err)
	}
	return parsed.Unmap(), nil
}
