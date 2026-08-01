package database

import (
	"testing"

	"github.com/dgraph-io/badger/v4"
)

func TestOpen_Memory(t *testing.T) {
	db, err := Open("", nil)
	if err != nil {
		t.Fatalf("Open(:memory:, 0) error: %v", err)
	}
	if db.Badger == nil {
		t.Fatal("db.Badger is nil")
	}
	if db.IsClosed() {
		t.Error("newly opened db should not be closed")
	}
	_ = db.Close()
}

func TestOpen_DefaultOpts(t *testing.T) {
	db, err := Open("", nil)
	if err != nil {
		t.Fatalf("Open with zero opts error: %v", err)
	}
	_ = db.Close()
}

func TestClose(t *testing.T) {
	db, err := Open("", nil)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("Close error: %v", err)
	}
	if !db.IsClosed() {
		t.Error("db should be closed after Close()")
	}
}

func TestClose_DoubleClose(t *testing.T) {
	db, err := Open("", nil)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("first Close error: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("second Close error: %v", err)
	}
}

func TestSequenceIDs(t *testing.T) {
	db, err := Open("", nil)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	id1, err := db.NextEntryID()
	if err != nil {
		t.Fatalf("NextEntryID error: %v", err)
	}
	id2, err := db.NextEntryID()
	if err != nil {
		t.Fatalf("NextEntryID error: %v", err)
	}
	if id2 <= id1 {
		t.Errorf("IDs should be monotonic: got %d then %d", id1, id2)
	}
}

func TestKeyRoundTrip(t *testing.T) {
	db, err := Open("", nil)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Write a cache entry and read it back — value is raw DNS wire.
	key := EntryKey("example.com.", "", 0, false, 1, 1)
	msgWire := []byte("test-wire")
	e := badger.NewEntry(key, msgWire)
	e.UserMeta = UserMetaValidated(true)
	// ExpiresAt=0 means no expiry (BadgerDB default).

	err = db.Badger.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(e)
	})
	if err != nil {
		t.Fatalf("SetEntry error: %v", err)
	}

	err = db.Badger.View(func(txn *badger.Txn) error {
		item, e := txn.Get(key)
		if e != nil {
			t.Errorf("Get error: %v", e)
			return nil
		}
		if item.UserMeta() != UserMetaValidated(true) {
			t.Errorf("UserMeta = %d, want %d", item.UserMeta(), UserMetaValidated(true))
		}
		return item.Value(func(v []byte) error {
			if string(v) != "test-wire" {
				t.Errorf("wire = %q, want %q", v, "test-wire")
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("View error: %v", err)
	}
}

func TestUserMetaRoundTrip(t *testing.T) {
	if meta := UserMetaValidated(true); meta != 1 {
		t.Errorf("UserMetaValidated(true) = %d, want 1", meta)
	}
	if meta := UserMetaValidated(false); meta != 0 {
		t.Errorf("UserMetaValidated(false) = %d, want 0", meta)
	}
}

func TestExpiresAtRoundTrip(t *testing.T) {
	// 894449f: ExpiresAt is set directly (not via WithTTL) and read back via
	// item.ExpiresAt(). The timestamp in cache.Get() is derived from:
	//   timestamp = expiresAt - entryTTL - staleMaxAge
	db, err := Open("", nil)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	key := EntryKey("example.com.", "", 0, false, 1, 1)
	futureExpiry := uint64(2_000_000_000)

	e := badger.NewEntry(key, []byte("wire"))
	e.ExpiresAt = futureExpiry

	err = db.Badger.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(e)
	})
	if err != nil {
		t.Fatalf("SetEntry error: %v", err)
	}

	err = db.Badger.View(func(txn *badger.Txn) error {
		item, e := txn.Get(key)
		if e != nil {
			return e
		}
		if item.ExpiresAt() != futureExpiry {
			t.Errorf("ExpiresAt = %d, want %d", item.ExpiresAt(), futureExpiry)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View error: %v", err)
	}
}

func TestPtrMapKeyRoundTrip(t *testing.T) {
	db, err := Open("", nil)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	key := EIPReverseKey("1.2.3.4", 42, "example.com.")
	val := EncodePtrMapValue(300, 1700000000)

	err = db.Badger.Update(func(txn *badger.Txn) error {
		return txn.Set(key, val)
	})
	if err != nil {
		t.Fatalf("Set error: %v", err)
	}

	err = db.Badger.View(func(txn *badger.Txn) error {
		item, e := txn.Get(key)
		if e != nil {
			t.Errorf("Get error: %v", e)
			return nil
		}
		return item.Value(func(v []byte) error {
			ttl := DecodePtrMapValue(v)
			if ttl != 300 {
				t.Errorf("ttl = %d, want 300", ttl)
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("View error: %v", err)
	}

	// Test prefix scan.
	_ = db.Badger.Update(func(txn *badger.Txn) error {
		return txn.Set(EIPReverseKey("1.2.3.4", 43, "other.com."), EncodePtrMapValue(600, 1700000000))
	})

	err = db.Badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = EIPReversePrefix("1.2.3.4")
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()

		count := 0
		for it.Rewind(); it.Valid(); it.Next() {
			count++
		}
		if count != 2 {
			t.Errorf("prefix scan count = %d, want 2", count)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View error: %v", err)
	}
}

func TestLatencyValueRoundTrip(t *testing.T) {
	val := EncodeLatencyValue(50)
	lat := DecodeLatencyValue(val)
	if lat != 50 {
		t.Errorf("latency = %d, want 50", lat)
	}
}

func TestOpen_Disk(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir+"/test.db", nil)
	if err != nil {
		t.Fatalf("Open(disk, 0) error: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Write something and verify it persists.
	err = db.Badger.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("test-key"), []byte("test-value"))
	})
	if err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	// Re-open and verify the data survived.
	db2, err := Open(dir+"/test.db", nil)
	if err != nil {
		t.Fatalf("Re-open error: %v", err)
	}
	defer func() { _ = db2.Close() }()

	err = db2.Badger.View(func(txn *badger.Txn) error {
		item, e := txn.Get([]byte("test-key"))
		if e != nil {
			t.Errorf("Get after reopen: %v", e)
			return nil
		}
		return item.Value(func(v []byte) error {
			if string(v) != "test-value" {
				t.Errorf("value = %q, want %q", v, "test-value")
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("View error: %v", err)
	}
}
