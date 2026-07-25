package lrumap

import (
	"bytes"
	"testing"

	"github.com/pion/dtls/v3"
)

func TestDTLSSessionStore_SetGet(t *testing.T) {
	s := NewDTLSSessionStore(10)
	key := []byte("example.com")
	sess := dtls.Session{ID: []byte{1, 2, 3}, Secret: []byte{4, 5, 6}}

	if err := s.Set(key, sess); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.ID, sess.ID) || !bytes.Equal(got.Secret, sess.Secret) {
		t.Errorf("got %+v, want %+v", got, sess)
	}
}

func TestDTLSSessionStore_GetMiss(t *testing.T) {
	s := NewDTLSSessionStore(10)
	sess, err := s.Get([]byte("nonexistent"))
	if err != nil {
		t.Errorf("Get should not return an error for missing key (got: %v)", err)
	}
	if sess.ID != nil {
		t.Error("Get should return zero-value session for missing key")
	}
}

func TestDTLSSessionStore_Del(t *testing.T) {
	s := NewDTLSSessionStore(10)
	key := []byte("example.com")
	sess := dtls.Session{ID: []byte{1}}

	if err := s.Set(key, sess); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := s.Del(key); err != nil {
		t.Fatalf("Del: %v", err)
	}

	sess2, err := s.Get(key)
	if err != nil {
		t.Errorf("Get should not return an error after Del (got: %v)", err)
	}
	if sess2.ID != nil {
		t.Error("Get should return zero-value session after Del")
	}
}

func TestDTLSSessionStore_Update(t *testing.T) {
	s := NewDTLSSessionStore(10)
	key := []byte("example.com")

	if err := s.Set(key, dtls.Session{ID: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(key, dtls.Session{ID: []byte{2}}); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.ID, []byte{2}) {
		t.Errorf("got ID %v, want [2]", got.ID)
	}
}

func TestDTLSSessionStore_Eviction(t *testing.T) {
	s := NewDTLSSessionStore(3)

	// Fill the cache with 5 entries — first 2 should be evicted.
	for i := range 5 {
		key := []byte{byte('a' + i)}
		if err := s.Set(key, dtls.Session{ID: key}); err != nil {
			t.Fatal(err)
		}
	}

	// First two keys should be evicted (nil ID returned).
	if sess, _ := s.Get([]byte("a")); sess.ID != nil {
		t.Error("key 'a' should have been evicted")
	}
	if sess, _ := s.Get([]byte("b")); sess.ID != nil {
		t.Error("key 'b' should have been evicted")
	}
	// Last three should be present.
	for _, k := range []byte{'c', 'd', 'e'} {
		if sess, err := s.Get([]byte{k}); err != nil || sess.ID == nil {
			t.Errorf("key %q should still be present (err=%v, id=%v)", k, err, sess.ID)
		}
	}
}

func TestDTLSSessionStore_DelNonExistent(t *testing.T) {
	s := NewDTLSSessionStore(10)
	// Should not panic.
	if err := s.Del([]byte("nonexistent")); err != nil {
		t.Fatalf("Del: %v", err)
	}
}
