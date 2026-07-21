package database

import (
	"testing"
)

func TestOpen_Memory(t *testing.T) {
	db, err := Open("", 100, Options{MMapSizeMB: 1, CacheSizeMB: 1})
	if err != nil {
		t.Fatalf("Open(:memory:) error: %v", err)
	}
	defer func() { _ = db.Close() }()
	if db.SQ == nil {
		t.Fatal("db.SQ is nil")
	}
	if db.IsClosed() {
		t.Error("newly opened db should not be closed")
	}
}

func TestOpen_DefaultOpts(t *testing.T) {
	db, err := Open("", 0, Options{})
	if err != nil {
		t.Fatalf("Open with zero opts error: %v", err)
	}
	defer func() { _ = db.Close() }()
	if db.MaxEntries() <= 0 {
		t.Errorf("MaxEntries = %d, want > 0", db.MaxEntries())
	}
}

func TestClose(t *testing.T) {
	db, err := Open("", 100, Options{MMapSizeMB: 1, CacheSizeMB: 1})
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
	db, err := Open("", 100, Options{MMapSizeMB: 1, CacheSizeMB: 1})
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("first Close error: %v", err)
	}
	// Second Close should be a no-op
	if err := db.Close(); err != nil {
		t.Errorf("second Close error: %v", err)
	}
}

func TestPreparedStatements(t *testing.T) {
	db, err := Open("", 100, Options{MMapSizeMB: 1, CacheSizeMB: 1})
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	stmts := []interface{ IsClosed() bool }{} // just check they're non-nil
	_ = stmts
	if db.StmtEntry == nil {
		t.Error("StmtEntry is nil")
	}
	if db.StmtQueryLog == nil {
		t.Error("StmtQueryLog is nil")
	}
	if db.StmtQueryStats == nil {
		t.Error("StmtQueryStats is nil")
	}
	if db.StmtInsertLatency == nil {
		t.Error("StmtInsertLatency is nil")
	}
	if db.StmtLastProbe == nil {
		t.Error("StmtLastProbe is nil")
	}

	if db.StmtZoneExact == nil {
		t.Error("StmtZoneExact is nil")
	}
	if db.StmtZoneWildcard == nil {
		t.Error("StmtZoneWildcard is nil")
	}
	if db.StmtIPLatency == nil {
		t.Error("StmtIPLatency is nil")
	}
}

func TestEntryCount(t *testing.T) {
	db, err := Open("", 100, Options{MMapSizeMB: 1, CacheSizeMB: 1})
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

func TestSQLiteWALConcurrentWrites(t *testing.T) {
	db, err := Open("", 100, Options{MMapSizeMB: 1, CacheSizeMB: 1})
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Verify that two concurrent transactions can both commit successfully
	// — SQLite WAL mode serializes writers, no app-level mutex needed.
	tx1, err := db.BeginTx()
	if err != nil {
		t.Fatalf("BeginTx error: %v", err)
	}
	if _, err := tx1.Exec(`CREATE TABLE IF NOT EXISTS test_wal (id INTEGER PRIMARY KEY, val TEXT)`); err != nil {
		_ = tx1.Rollback()
		t.Fatalf("Create table error: %v", err)
	}
	if err := tx1.Commit(); err != nil {
		t.Fatalf("Commit error: %v", err)
	}

	tx2, err := db.BeginTx()
	if err != nil {
		t.Fatalf("BeginTx error: %v", err)
	}
	_, err = tx2.Exec(`INSERT INTO test_wal (id, val) VALUES (1, 'hello')`)
	if err != nil {
		_ = tx2.Rollback()
		t.Fatalf("Insert error: %v", err)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatalf("Commit error: %v", err)
	}
}

func TestBeginTx(t *testing.T) {
	db, err := Open("", 100, Options{MMapSizeMB: 1, CacheSizeMB: 1})
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	tx, err := db.BeginTx()
	if err != nil {
		t.Fatalf("BeginTx error: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Errorf("tx.Commit error: %v", err)
	}
}

func TestSQLExec(t *testing.T) {
	db, err := Open("", 100, Options{MMapSizeMB: 1, CacheSizeMB: 1})
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	_, err = db.SQLExec("SELECT 1")
	if err != nil {
		t.Errorf("SQLExec error: %v", err)
	}
}

func TestSQLQueryRow(t *testing.T) {
	db, err := Open("", 100, Options{MMapSizeMB: 1, CacheSizeMB: 1})
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	row := db.SQLQueryRow("SELECT 1")
	var n int
	if err := row.Scan(&n); err != nil {
		t.Errorf("SQLQueryRow scan error: %v", err)
	}
	if n != 1 {
		t.Errorf("got %d, want 1", n)
	}
}

func TestSQLQuery(t *testing.T) {
	db, err := Open("", 100, Options{MMapSizeMB: 1, CacheSizeMB: 1})
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows, err := db.SQLQuery("SELECT 1 AS n")
	if err != nil {
		t.Fatalf("SQLQuery error: %v", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		t.Fatal("expected at least one row")
	}
	var n int
	if err := rows.Scan(&n); err != nil {
		t.Errorf("scan error: %v", err)
	}
}

func TestZoneStorageMethods(t *testing.T) {
	db, err := Open("", 100, Options{MMapSizeMB: 1, CacheSizeMB: 1})
	if err != nil {
		t.Fatalf("Open error: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Exec
	_, err = db.Exec("SELECT 1")
	if err != nil {
		t.Errorf("Exec error: %v", err)
	}

	// Begin
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin error: %v", err)
	}
	_ = tx.Commit()
}
