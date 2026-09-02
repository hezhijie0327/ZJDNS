package dnsutil

import "time"

// LeafNotAfter clamps a leaf certificate's notAfter to its CA's: the leaf
// must never outlive its signer.  Shared by the TLS and TLCP self-signed
// cert generators (previously duplicated byte-for-byte, P-L9).
func LeafNotAfter(now, caNotAfter time.Time, validity time.Duration) time.Time {
	leaf := now.Add(validity)
	if caNotAfter.Before(leaf) {
		return caNotAfter
	}
	return leaf
}
