package resolver

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	zdnsutil "zjdns/internal/dnsutil"
)

const (
	rootHintsFileName = "named.root"
	rootHintsURL      = "https://www.internic.net/domain/named.root"

	// rootHintsKey is the single entry holding the whole root table.
	rootHintsKey = "hints"
)

var errNoRootHints = errors.New("no root servers found")

// lastLoadErrAt throttles the Error log for repeated load failures — the
// retry-on-next-query design would otherwise print one Error per recursive
// query while the data file is missing (hot-path spam drowning real signals).
var lastLoadErrAt atomic.Int64

// rootHints maps root server FQDNs to their addresses (ip:port), stored as a
// single-entry lrumap (capacity 1 — LRU eviction can never displace the
// table; the map just provides the shared concurrent container). Lazily
// populated from named.root on first access; empty until then.
var rootHints = lrumap.New[string, map[string][]string](1)

// LoadRootHints eagerly loads root server hints from named.root. Only needed
// for recursive resolution; upstream-only deployments can skip this call.
func LoadRootHints() {
	loadHints()
}

// loadHints returns the root server hints, loading from named.root on first
// access. A failed load is NOT permanently cached: sync.Once would leave the
// resolver with zero root servers for the rest of the process lifetime, so a
// failed attempt is retried on the next call. Returns an empty map on failure.
// Concurrent misses both load the file (idempotent, harmless) and Set the
// same table.
func loadHints() map[string][]string {
	if hints, ok := rootHints.Get(rootHintsKey); ok {
		return hints
	}

	path := zdnsutil.ResolveDataFile(rootHintsFileName, rootHintsURL)
	if path == "" {
		logLoadError("cannot determine root hints path — no root hints loaded")
		return nil
	}
	hints, err := loadRootHintsFromFile(path)
	if err != nil {
		logLoadError(fmt.Sprintf("failed to load root hints from %s: %v — will retry on next query", path, err))
		// Do NOT cache the failure: a nil map here means the next call
		// retries. Caching an empty map would permanently disable root
		// resolution after one transient failure (e.g. startup offline).
		return nil
	}
	rootHints.Set(rootHintsKey, hints)
	log.Infof("RECURSION: loaded %d root server(s) from %s", len(hints), path)
	return hints
}

// logLoadError logs a root-hints load failure at Error level at most once per
// minute; the intervening failures go to Debug.
func logLoadError(msg string) {
	now := log.NowUnix()
	if now-lastLoadErrAt.Load() >= 60 {
		lastLoadErrAt.Store(now)
		log.Errorf("RECURSION: %s", msg)
	} else {
		log.Debugf("RECURSION: %s", msg)
	}
}

// loadRootHintsFromFile parses a BIND-style named.root zone file and returns a
// map of root server FQDN → "ip:port" addresses.
func loadRootHintsFromFile(path string) (map[string][]string, error) {
	//nolint:gosec // path is derived from os.Executable(), not user input
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	nsNames := make(map[string]struct{})
	aRecords := make(map[string][]string)

	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		rr, err := dns.New(line)
		if err != nil {
			// A single malformed line silently dropping that root server is
			// hard to diagnose when enough lines are corrupted.
			log.Debugf("RECURSION: skipping malformed root hints line %q: %v", line, err)
			continue
		}
		hdr := rr.Header()
		switch rr := rr.(type) {
		case *dns.NS:
			if hdr.Name == "." {
				nsNames[dnsutil.Fqdn(rr.Ns)] = struct{}{}
			}
		case *dns.A:
			aRecords[strings.ToLower(hdr.Name)] = append(aRecords[strings.ToLower(hdr.Name)],
				net.JoinHostPort(rr.A.String(), config.DefaultUDPPort))
		case *dns.AAAA:
			aRecords[strings.ToLower(hdr.Name)] = append(aRecords[strings.ToLower(hdr.Name)],
				net.JoinHostPort(rr.AAAA.String(), config.DefaultUDPPort))
		}
	}

	hints := make(map[string][]string, len(nsNames))
	for name := range nsNames {
		// Normalize keys to lowercase: every other name key in this file is
		// lowercased, and a case-sensitive index into the returned map would
		// silently miss root servers.
		key := strings.ToLower(name)
		if addrs := aRecords[key]; len(addrs) > 0 {
			hints[key] = addrs
		}
	}

	if len(hints) == 0 {
		return nil, errNoRootHints
	}
	return hints, nil
}
