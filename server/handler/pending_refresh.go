package handler

import (
	"zjdns/edns"
	"zjdns/internal/log"
)

// tryStartRefresh builds a pendingKey from the given parameters and attempts
// to register a cache refresh. Returns true if the caller should proceed
// (leader), false if a refresh is already in flight. All refresh paths use
// dnssecOK=false since refreshCacheEntry always caches with dnssecOK=false.
func (h *Handler) tryStartRefresh(qname string, qtype, qclass uint16, ecs *edns.ECSOption) bool {
	if h.pendingRefreshes == nil {
		return true
	}
	key := buildPendingKey(qname, qtype, qclass, ecs, false)
	if !h.pendingRefreshes.Start(key) {
		log.Debugf("CACHE: refresh skipped for %s — already in flight", qname)
		return false
	}
	return true
}

// finishRefresh removes the pending refresh key after the refresh goroutine
// completes (whether success or failure).
func (h *Handler) finishRefresh(qname string, qtype, qclass uint16, ecs *edns.ECSOption) {
	if h.pendingRefreshes == nil {
		return
	}
	key := buildPendingKey(qname, qtype, qclass, ecs, false)
	h.pendingRefreshes.Done(key)
}
