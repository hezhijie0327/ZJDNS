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

	// Write an entry and read it back.
	key := EntryKey("example.com.", "", 0, false, 1, 1)
	val := EncodeEntryValue(42, 1000, 300, []byte("test-wire"))
	entry := badger.NewEntry(key, val).WithMeta(UserMetaValidated(true))

	err = db.Badger.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(entry)
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
		if item.UserMeta() != 1 {
			t.Errorf("UserMeta = %d, want 1", item.UserMeta())
		}
		return item.Value(func(v []byte) error {
			id, ts, ttl, wire := DecodeEntryValue(v)
			if id != 42 {
				t.Errorf("id = %d, want 42", id)
			}
			if ts != 1000 {
				t.Errorf("ts = %d, want 1000", ts)
			}
			if ttl != 300 {
				t.Errorf("ttl = %d, want 300", ttl)
			}
			if string(wire) != "test-wire" {
				t.Errorf("wire = %q, want %q", wire, "test-wire")
			}
			return nil
		})
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
	val := EncodePtrMapValue(300)

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
		return txn.Set(EIPReverseKey("1.2.3.4", 43, "other.com."), EncodePtrMapValue(600))
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
