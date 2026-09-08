package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"

	"github.com/acexy/portway/internal/protocol"
)

const maxCachedConfigurationRequests = 16

type configurationRequestRecord struct {
	revision    uint64
	fingerprint [sha256.Size]byte
	result      protocol.SyncConfigurationResult
}

type configurationSyncState struct {
	revision     uint64
	fingerprint  [sha256.Size]byte
	result       protocol.SyncConfigurationResult
	requests     map[string]configurationRequestRecord
	requestOrder []string
}

func configurationSyncKey(clientID string, sessionID string) string {
	return clientID + "\x00" + sessionID
}

func (s *Service) checkConfigurationSync(
	clientID string,
	sessionID string,
	requestID string,
	request protocol.SyncConfiguration,
) (*protocol.SyncConfigurationResult, *protocol.ConfigurationError) {
	if err := protocol.ValidateRequestID(requestID); err != nil {
		return nil, invalidConfigurationRequest(err.Error())
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, invalidConfigurationRequest("encode complete configuration")
	}
	fingerprint := sha256.Sum256(payload)
	key := configurationSyncKey(clientID, sessionID)

	s.configurationSyncMutex.Lock()
	defer s.configurationSyncMutex.Unlock()
	if s.configurationSyncStates == nil {
		s.configurationSyncStates = make(map[string]*configurationSyncState)
	}
	state := s.configurationSyncStates[key]
	if state == nil {
		return nil, nil
	}
	if cached, exists := state.requests[requestID]; exists {
		if cached.revision == request.Revision &&
			subtle.ConstantTimeCompare(cached.fingerprint[:], fingerprint[:]) == 1 {
			result := cached.result
			return &result, nil
		}
		return nil, invalidConfigurationRequest("configuration request ID payload changed")
	}
	if request.Revision == 0 || request.Revision < state.revision {
		return nil, invalidConfigurationRequest("configuration revision is stale")
	}
	if request.Revision == state.revision {
		if subtle.ConstantTimeCompare(state.fingerprint[:], fingerprint[:]) == 1 {
			result := state.result
			return &result, nil
		}
		return nil, invalidConfigurationRequest("configuration revision payload changed")
	}
	return nil, nil
}

func (s *Service) cacheConfigurationSync(
	clientID string,
	sessionID string,
	requestID string,
	request protocol.SyncConfiguration,
	result protocol.SyncConfigurationResult,
) {
	payload, err := json.Marshal(request)
	if err != nil {
		return
	}
	fingerprint := sha256.Sum256(payload)
	key := configurationSyncKey(clientID, sessionID)
	s.configurationSyncMutex.Lock()
	defer s.configurationSyncMutex.Unlock()
	if s.configurationSyncStates == nil {
		s.configurationSyncStates = make(map[string]*configurationSyncState)
	}
	state := s.configurationSyncStates[key]
	if state == nil {
		state = &configurationSyncState{requests: make(map[string]configurationRequestRecord)}
		s.configurationSyncStates[key] = state
	}
	if len(state.requestOrder) == maxCachedConfigurationRequests {
		oldest := state.requestOrder[0]
		state.requestOrder = state.requestOrder[1:]
		delete(state.requests, oldest)
	}
	state.requestOrder = append(state.requestOrder, requestID)
	state.requests[requestID] = configurationRequestRecord{
		revision: request.Revision, fingerprint: fingerprint, result: result,
	}
	state.revision = request.Revision
	state.fingerprint = fingerprint
	state.result = result
}

func (s *Service) clearConfigurationSync(clientID string, sessionID string) {
	s.configurationSyncMutex.Lock()
	delete(s.configurationSyncStates, configurationSyncKey(clientID, sessionID))
	s.configurationSyncMutex.Unlock()
}

func invalidConfigurationRequest(message string) *protocol.ConfigurationError {
	return &protocol.ConfigurationError{
		Code:      protocol.ConfigurationErrorCode("invalid_request"),
		Message:   message,
		Retryable: false,
	}
}
