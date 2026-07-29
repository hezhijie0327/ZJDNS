package database

import (
	"testing"

	"github.com/dgraph-io/badger/v4"
)

func TestOpen_Memory(t *testing.T) {
	db, err := Open("", 100, 0, 0)
	if err != nil {
		t.Fatalf("Open(:memory:) error: %v", err)
	}
	defer func() { _ = db.Close() }()
	if db.Badger == nil {
		t.Fatal("db.Badger is nil")
	}
	if db.IsClosed() {
		t.Error("newly opened db should not be closed")
	}
}

func TestOpen_DefaultOpts(t *testing.T) {
	db, err := Open("", 0, 0, 0)
	if err != nil {
		t.Fatalf("Open with zero opts error: %v", err)
	}
	defer func() { _ = db.Close() }()
	if db.MaxEntries() <= 0 {
		t.Errorf("MaxEntries = %d, want > 0", db.MaxEntries())
	}
}

func TestClose(t *testing.T) {
	db, err := Open("", 100, 0, 0)
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
	db, err := Open("", 100, 0, 0)
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

func TestEntryCount(t *testing.T) {
	db, err := Open("", 100, 0, 0)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	if db.EntryCount() != 0 {
		t.Errorf("initial EntryCount = %d, want 0", db.EntryCount())
	}
	db.AddEntryCount(5)
	if db.EntryCount() != 5 {
		t.Errorf("EntryCount after AddEntryCount(5) = %d, want 5", db.EntryCount())
	}
	db.SetEntryCount(10)
	if db.EntryCount() != 10 {
		t.Errorf("EntryCount after SetEntryCount(10) = %d, want 10", db.EntryCount())
	}
}

func TestSequenceIDs(t *testing.T) {
	db, err := Open("", 100, 0, 0)
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

	qid1, err := db.NextQLogID()
	if err != nil {
		t.Fatalf("NextQLogID error: %v", err)
	}
	qid2, err := db.NextQLogID()
	if err != nil {
		t.Fatalf("NextQLogID error: %v", err)
	}
	if qid2 <= qid1 {
		t.Errorf("IDs should be monotonic: got %d then %d", qid1, qid2)
	}
}

func TestKeyRoundTrip(t *testing.T) {
	db, err := Open("", 100, 0, 0)
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
	db, err := Open("", 100, 0, 0)
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	key := PtrMapKey("1.2.3.4", 42, "example.com.")
	val := EncodePtrMapValue(300, 1300)

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
			ttl, expiresAt := DecodePtrMapValue(v)
			if ttl != 300 {
				t.Errorf("ttl = %d, want 300", ttl)
			}
			if expiresAt != 1300 {
				t.Errorf("expiresAt = %d, want 1300", expiresAt)
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("View error: %v", err)
	}

	// Test prefix scan.
	_ = db.Badger.Update(func(txn *badger.Txn) error {
		return txn.Set(PtrMapKey("1.2.3.4", 43, "other.com."), EncodePtrMapValue(600, 1600))
	})

	err = db.Badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = PtrMapIPPrefix("1.2.3.4")
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
	val := EncodeLatencyValue(28, 50, 2000)
	qtype, lat, probe := DecodeLatencyValue(val)
	if qtype != 28 {
		t.Errorf("qtype = %d, want 28", qtype)
	}
	if lat != 50 {
		t.Errorf("latency = %d, want 50", lat)
	}
	if probe != 2000 {
		t.Errorf("probe = %d, want 2000", probe)
	}
}

func TestQueryStatsValueRoundTrip(t *testing.T) {
	val := EncodeQueryStatsValue(10, 500)
	count, ms := DecodeQueryStatsValue(val)
	if count != 10 {
		t.Errorf("count = %d, want 10", count)
	}
	if ms != 500 {
		t.Errorf("ms = %d, want 500", ms)
	}
}

func TestZoneValueRoundTrip(t *testing.T) {
	val := EncodeZoneValue(3, []byte("ans"), []byte("auth"), []byte("add"))
	rcode, ans, auth, add := DecodeZoneValue(val)
	if rcode != 3 {
		t.Errorf("rcode = %d, want 3", rcode)
	}
	if string(ans) != "ans" {
		t.Errorf("answer = %q, want %q", ans, "ans")
	}
	if string(auth) != "auth" {
		t.Errorf("authority = %q, want %q", auth, "auth")
	}
	if string(add) != "add" {
		t.Errorf("additional = %q, want %q", add, "add")
	}
}

func TestEncodeDecodeQueryLogValue(t *testing.T) {
	val := EncodeQueryLogValue(1000, "example.com.", 1, 1, "tls", "miss", 3, 25, "1.1.1.1", 1, "secure")
	ts, qname, qtype, qclass, protocol, result, rcode, responseMS, server, poisoned, dnssec := DecodeQueryLogValue(val)
	if ts != 1000 {
		t.Errorf("ts = %d, want 1000", ts)
	}
	if qname != "example.com." {
		t.Errorf("qname = %q, want %q", qname, "example.com.")
	}
	if qtype != 1 {
		t.Errorf("qtype = %d, want 1", qtype)
	}
	if qclass != 1 {
		t.Errorf("qclass = %d, want 1", qclass)
	}
	if protocol != "tls" {
		t.Errorf("protocol = %q, want %q", protocol, "tls")
	}
	if result != "miss" {
		t.Errorf("result = %q, want %q", result, "miss")
	}
	if rcode != 3 {
		t.Errorf("rcode = %d, want 3", rcode)
	}
	if responseMS != 25 {
		t.Errorf("responseMS = %d, want 25", responseMS)
	}
	if server != "1.1.1.1" {
		t.Errorf("server = %q, want %q", server, "1.1.1.1")
	}
	if poisoned != 1 {
		t.Errorf("poisoned = %d, want 1", poisoned)
	}
	if dnssec != "secure" {
		t.Errorf("dnssec = %q, want %q", dnssec, "secure")
	}
}

func TestOpen_Disk(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir+"/test.db", 100, 0, 0)
	if err != nil {
		t.Fatalf("Open(disk) error: %v", err)
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
	db2, err := Open(dir+"/test.db", 100, 0, 0)
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
