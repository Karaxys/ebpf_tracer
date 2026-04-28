package main

import "time"

func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{
		sessions: make(map[string]*StreamState),
		ttl:      ttl,
	}
}

func (s *sessionStore) getOrCreate(key string) *StreamState {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, exists := s.sessions[key]
	if !exists {
		state = &StreamState{LastActive: time.Now()}
		s.sessions[key] = state
	}

	return state
}

func (s *sessionStore) get(key string) (*StreamState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.sessions[key]
	return state, ok
}

func (s *sessionStore) remove(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, key)
}

func (s *sessionStore) cleanupExpired(cutoff time.Time, onExpire func(*StreamState) int) (int, int) {
	s.mu.Lock()

	expired := make([]*StreamState, 0)
	for key, state := range s.sessions {
		state.mu.Lock()
		isExpired := state.LastActive.Before(cutoff)
		state.mu.Unlock()
		if isExpired {
			delete(s.sessions, key)
			expired = append(expired, state)
		}
	}
	s.mu.Unlock()

	parsed := 0
	if onExpire != nil {
		for _, state := range expired {
			parsed += onExpire(state)
		}
	}

	return len(expired), parsed
}
