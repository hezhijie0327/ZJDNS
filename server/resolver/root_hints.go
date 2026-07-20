package resolver

import (
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"zjdns/config"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	zdnsutil "zjdns/internal/dnsutil"
)

const (
	rootHintsFileName = "named.root"
	rootHintsURL      = "https://www.internic.net/domain/named.root"
)

var errNoRootHints = errors.New("no root servers found")

// rootHints maps root server FQDNs to their addresses (ip:port).
// Lazily populated from named.root on first access; empty until then.
var (
	rootHints     map[string][]string
	rootHintsOnce sync.Once
)

// LoadRootHints eagerly loads root server hints from named.root. Only needed
// for recursive resolution; upstream-only deployments can skip this call.
func LoadRootHints() {
	loadHints()
}

// loadHints returns the root server hints, loading from named.root on first
// access via sync.Once. Returns an empty map on failure.
func loadHints() map[string][]string {
	rootHintsOnce.Do(func() {
		rootHints = make(map[string][]string)

		path := zdnsutil.ResolveDataFile(rootHintsFileName, rootHintsURL)
		if path == "" {
			log.Errorf("RECURSION: cannot determine root hints path — no root hints loaded")
			return
		}
		hints, err := loadRootHintsFromFile(path)
		if err != nil {
			log.Errorf("RECURSION: failed to load root hints from %s: %v", path, err)
			return
		}
		rootHints = hints
		log.Infof("RECURSION: loaded %d root server(s) from %s", len(hints), path)
	})
	return rootHints
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
		key := strings.ToLower(name)
		if addrs := aRecords[key]; len(addrs) > 0 {
			hints[name] = addrs
		}
	}

	if len(hints) == 0 {
		return nil, errNoRootHints
	}
	return hints, nil
}
