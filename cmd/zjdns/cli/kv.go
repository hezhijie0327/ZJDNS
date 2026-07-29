package cli

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"zjdns/database"

	"github.com/dgraph-io/badger/v4"
)

var knownPrefixes = []string{
	"e:", "p:", "l:", "s:", "q:", "z:", "r:",
}

var prefixLabels = map[string]string{
	"e:": "cache entries",
	"p:": "ptr_map (IP→domain)",
	"l:": "IP latency",
	"s:": "query_stats (per-day)",
	"q:": "query_log (audit trail)",
	"z:": "zone entries",
	"r:": "ruleset entries",
}

// RunKV opens a BadgerDB database and browses keys by prefix. If prefix is
// empty, lists all key prefixes with counts. If prefix is non-empty, decodes
// and displays all keys with that prefix.
func RunKV(dbPath, prefix string) error {
	db, err := database.Open(dbPath, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	if prefix == "" {
		return listPrefixes(db)
	}
	return dumpPrefix(db, prefix)
}

// RunKVDrop drops all keys with the given prefix. Prompts for confirmation.
func RunKVDrop(dbPath, prefix string) error {
	db, err := database.Open(dbPath, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	fmt.Fprintf(os.Stderr, "Drop all keys with prefix %q? [y/N] ", prefix)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return errors.New("no input")
	}
	resp := strings.TrimSpace(scanner.Text())
	if resp != "y" && resp != "Y" {
		return errors.New("aborted")
	}

	if err := db.Badger.DropPrefix([]byte(prefix)); err != nil {
		return fmt.Errorf("drop prefix: %w", err)
	}
	fmt.Fprintf(os.Stderr, "dropped prefix %q\n", prefix)
	return nil
}

func listPrefixes(db *database.DB) error {
	prefixes := map[string]int{}
	_ = db.Badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			k := string(it.Item().Key())
			for _, p := range knownPrefixes {
				if strings.HasPrefix(k, p) {
					prefixes[p]++
					break
				}
			}
		}
		return nil
	})

	fmt.Printf("%-5s %-25s %s\n", "Key", "Table", "Count")
	fmt.Printf("%-5s %-25s %s\n", "---", "-----", "-----")
	for _, p := range knownPrefixes {
		if n, ok := prefixes[p]; ok {
			fmt.Printf("%-5s %-25s %d\n", p, prefixLabels[p], n)
		}
	}
	return nil
}

func dumpPrefix(db *database.DB, prefix string) error {
	count := 0
	_ = db.Badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(prefix)
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := string(item.Key())
			_ = item.Value(func(v []byte) error {
				printDecoded(k, v)
				return nil
			})
			count++
		}
		return nil
	})
	fmt.Fprintf(os.Stderr, "%d key(s)\n", count)
	return nil
}

// printDecoded prints a human-readable line for a known key prefix.
func printDecoded(key string, val []byte) {
	switch {
	case strings.HasPrefix(key, "e:"):
		id, ts, ttl, _ := database.DecodeEntryValue(val)
		validated := "no"
		// validated is in UserMeta, not accessible here; decode from val length
		_ = validated
		fmt.Printf("id=%-4d ts=%-12d ttl=%-5d wire=%d B  key=%s\n", id, ts, ttl, len(val)-20, key)

	case strings.HasPrefix(key, "p:"):
		ttl, expiresAt := database.DecodePtrMapValue(val)
		fmt.Printf("ttl=%-5d expires=%-12d key=%s\n", ttl, expiresAt, key)

	case strings.HasPrefix(key, "l:"):
		qtype, latencyMS, lastProbe := database.DecodeLatencyValue(val)
		fmt.Printf("qtype=%-4d latency=%-5dms last_probe=%-12d key=%s\n", qtype, latencyMS, lastProbe, key)

	case strings.HasPrefix(key, "q:"):
		ts, qname, qtype, _, protocol, result, rcode, responseMS, server, poisoned, dnssec := database.DecodeQueryLogValue(val)
		t := time.Unix(ts, 0).UTC().Format(time.DateTime)
		flags := ""
		if poisoned != 0 {
			flags += " poisoned=1"
		}
		if dnssec != "" {
			flags += " dnssec=" + dnssec
		}
		fmt.Printf("%s qname=%-35s qtype=%-4d result=%-6s protocol=%-8s rcode=%-2d server=%-12s %4dms%s\n",
			t, qname, qtype, result, protocol, rcode, server, responseMS, flags)

	case strings.HasPrefix(key, "s:"):
		qc, tms := database.DecodeQueryStatsValue(val)
		// Parse key fields: s:{stat_day:08x}\x00{result}\x00{protocol}\x00...
		fmt.Printf("count=%-6d total_ms=%-8d key=%s\n", qc, tms, key)

	case strings.HasPrefix(key, "z:"):
		rcode, ans, auth, addl := database.DecodeZoneValue(val)
		fmt.Printf("rcode=%-2d answer=%-5d authority=%-5d additional=%-5d B  key=%s\n",
			rcode, len(ans), len(auth), len(addl), key)

	case strings.HasPrefix(key, "r:"):
		fmt.Printf("key=%s\n", key)

	default:
		fmt.Printf("[%d bytes] %s\n", len(val), hex.EncodeToString(val))
	}
}
