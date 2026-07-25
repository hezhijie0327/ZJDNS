package lrumap

import (
	"errors"

	"github.com/pion/dtls/v3"
)

// DTLSSessionStore implements dtls.SessionStore using an LRU-map backend.
// It is safe for concurrent use.
type DTLSSessionStore struct {
	cache *Map[string, dtls.Session]
}

// NewDTLSSessionStore creates a DTLSSessionStore with the given capacity.
func NewDTLSSessionStore(capacity int) *DTLSSessionStore {
	return &DTLSSessionStore{cache: New[string, dtls.Session](capacity)}
}

// Set saves a DTLS session. For clients, key is the server name; for servers,
// key is the session ID.
func (s *DTLSSessionStore) Set(key []byte, sess dtls.Session) error {
	s.cache.Set(string(key), sess)
	return nil
}

// Get fetches a DTLS session. Returns an error if the session is not found.
func (s *DTLSSessionStore) Get(key []byte) (dtls.Session, error) {
	sess, ok := s.cache.Get(string(key))
	if !ok {
		return dtls.Session{}, errors.New("dtls: session not found")
	}
	return sess, nil
}

// Del removes a saved DTLS session.
func (s *DTLSSessionStore) Del(key []byte) error {
	s.cache.Delete(string(key))
	return nil
}
