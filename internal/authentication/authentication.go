// Package authentication owns immutable server authentication records.
package authentication

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"sync/atomic"

	"github.com/acexy/golang-toolkit/util/coll"
)

// Mode identifies the server-controlled client management mode.
type Mode string

const (
	// ModeShared allows clients holding the deployment-wide Token to declare proxies.
	ModeShared Mode = "shared_token"
	// ModeGoverned allows client declarations within a server-owned permission policy.
	ModeGoverned Mode = "governed"
	// ModeManaged allows only server-owned proxy configuration.
	ModeManaged Mode = "managed"
)

// Context is the authenticated identity bound to a transport connection.
type Context struct {
	Mode         Mode
	ClientID     string
	CredentialID [sha256.Size]byte
	Generation   uint64
}

// Record is one immutable Token-backed authentication record.
type Record struct {
	Context Context
	Token   string
}

// Selector derives the public credential selector used before Token proof.
//
// Tokens contain more than 32 UTF-8 characters and should be generated from a
// cryptographically secure random source. The selector is not a credential and
// must never replace proof.
func Selector(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

// Snapshot is one fully validated authentication generation.
type Snapshot struct {
	records map[[sha256.Size]byte]Record
}

// NewSnapshot creates an immutable snapshot from globally unique records.
func NewSnapshot(records []Record) (*Snapshot, error) {
	index := make(map[[sha256.Size]byte]Record, len(records))
	for _, record := range records {
		selector := Selector(record.Token)
		if _, exists := index[selector]; exists {
			return nil, errors.New("authentication token must be globally unique")
		}
		record.Context.CredentialID = selector
		index[selector] = record
	}
	return &Snapshot{records: index}, nil
}

// IsCurrent reports whether a previously authenticated context still resolves
// to the same server-owned authentication record.
func (snapshot *Snapshot) IsCurrent(context Context) bool {
	if snapshot == nil {
		return false
	}
	record, exists := snapshot.records[context.CredentialID]
	return exists &&
		record.Context.Mode == context.Mode &&
		record.Context.ClientID == context.ClientID &&
		record.Context.Generation == context.Generation
}

// ContainsRecord reports whether a snapshot contains the same credential-owned identity.
func (snapshot *Snapshot) ContainsRecord(context Context) bool {
	if snapshot == nil {
		return false
	}
	record, exists := snapshot.records[context.CredentialID]
	return exists &&
		record.Context.Mode == context.Mode &&
		record.Context.ClientID == context.ClientID
}

// Resolve returns the record selected by a public Token digest.
func (snapshot *Snapshot) Resolve(selector []byte) (Record, bool) {
	if snapshot == nil || len(selector) != sha256.Size {
		return Record{}, false
	}
	var key [sha256.Size]byte
	copy(key[:], selector)
	record, exists := snapshot.records[key]
	return record, exists
}

// ContainsToken reports whether a Token is present without exposing it.
func (snapshot *Snapshot) ContainsToken(token string) bool {
	if snapshot == nil {
		return false
	}
	selector := Selector(token)
	record, exists := snapshot.records[selector]
	return exists &&
		subtle.ConstantTimeCompare([]byte(record.Token), []byte(token)) == 1
}

// Store atomically publishes immutable authentication snapshots.
type Store struct {
	current        atomic.Pointer[Snapshot]
	nextGeneration atomic.Uint64
}

// NewStore creates a store with an initial validated snapshot.
func NewStore(snapshot *Snapshot) *Store {
	store := &Store{}
	store.current.Store(snapshot.withGeneration(store.nextGeneration.Add(1)))
	return store
}

// Load returns the current immutable snapshot.
func (store *Store) Load() *Snapshot {
	return store.current.Load()
}

// Replace atomically publishes a new immutable snapshot.
func (store *Store) Replace(snapshot *Snapshot) {
	store.ReplaceRevoking(snapshot, nil)
}

// ReplaceRevoking publishes a snapshot while assigning a new generation to
// every retained authentication record whose current context is revoked.
func (store *Store) ReplaceRevoking(snapshot *Snapshot, revoked []Context) {
	current := store.Load()
	rotated := make(map[[sha256.Size]byte]struct{}, len(revoked))
	for _, context := range revoked {
		rotated[context.CredentialID] = struct{}{}
	}
	records := make(map[[sha256.Size]byte]Record, len(snapshot.records))
	for selector, record := range snapshot.records {
		if previous, exists := current.records[selector]; exists &&
			previous.Context.Mode == record.Context.Mode &&
			previous.Context.ClientID == record.Context.ClientID {
			if _, rotate := rotated[selector]; !rotate {
				record.Context.Generation = previous.Context.Generation
				records[selector] = record
				continue
			}
		}
		record.Context.Generation = store.nextGeneration.Add(1)
		records[selector] = record
	}
	store.current.Store(&Snapshot{records: records})
}

// Contexts returns the non-secret authentication contexts in this snapshot.
func (snapshot *Snapshot) Contexts() []Context {
	if snapshot == nil {
		return nil
	}
	contexts := coll.MapFilterToSlice(snapshot.records, func(_ [sha256.Size]byte, record Record) (Context, bool) {
		return record.Context, true
	})
	if contexts == nil {
		return []Context{}
	}
	return contexts
}

func (snapshot *Snapshot) withGeneration(generation uint64) *Snapshot {
	if snapshot == nil {
		return nil
	}
	records := coll.MapCollect(snapshot.records, func(selector [sha256.Size]byte, record Record) ([sha256.Size]byte, Record) {
		record.Context.Generation = generation
		return selector, record
	})
	if records == nil {
		records = map[[sha256.Size]byte]Record{}
	}
	return &Snapshot{records: records}
}

// Resolve resolves a selector against the current snapshot.
func (store *Store) Resolve(selector []byte) (Record, bool) {
	return store.Load().Resolve(selector)
}

// IsCurrent reports whether an authenticated context belongs to the current snapshot.
func (store *Store) IsCurrent(context Context) bool {
	return store.Load().IsCurrent(context)
}
