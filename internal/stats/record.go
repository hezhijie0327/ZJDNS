package stats

import "sync"

// RequestRecord captures per-query metadata. Every query updates the
// counters; non-hit results also enter the per-RCODE top-N domain journal.
type RequestRecord struct {
	Qname        string // normalized FQDN
	Qtype        uint16
	Qclass       uint16
	Protocol     string // 'udp','tcp','tls','quic','https','http3','dtls','dnscrypt','dnscrypt-tcp','tlcp','http-tlcp','dtlcp'
	Result       string // 'hit','miss','stale','zone','any','error','blocked','badcookie'
	ResponseTime int64  // milliseconds
	Rcode        int    // DNS response code
	Server       string // upstream server identifier
	Poisoned     bool   // true when DNS poison was detected
	DNSSECStatus string // 'secure','insecure','bogus', or ''
}

// requestRecordPool reuses RequestRecord structs — one is allocated per
// query on the recording path.
var requestRecordPool = sync.Pool{New: func() any { return new(RequestRecord) }}

// AcquireRequestRecord returns a zeroed RequestRecord from the pool.
func AcquireRequestRecord() *RequestRecord { return requestRecordPool.Get().(*RequestRecord) }

// ReleaseRequestRecord returns a record to the pool after Record.
func ReleaseRequestRecord(r *RequestRecord) {
	*r = RequestRecord{}
	requestRecordPool.Put(r)
}
