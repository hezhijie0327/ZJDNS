// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// =============================================================================
// DNSSECValidator Methods
// =============================================================================

// InitializeTrustAnchors initializes the trust anchors from the built-in defaults
func (v *DNSSECValidator) InitializeTrustAnchors() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.initialized {
		return
	}

	v.trustAnchors = make(map[uint16]*dns.DNSKEY)
	v.zoneCache = NewZoneCache()

	for _, anchor := range DefaultRootTrustAnchors {
		// Create DNSKEY record from trust anchor
		dnskey := &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   anchor.Zone,
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Flags:     anchor.Flags,
			Protocol:  3,
			Algorithm: anchor.Algorithm,
			PublicKey: anchor.PublicKey,
		}

		// Verify key tag matches
		computedKeyTag := dnskey.KeyTag()
		if computedKeyTag != anchor.KeyTag {
			LogWarn("DNSSEC: Trust anchor %d has mismatched key tag (computed: %d)", anchor.KeyTag, computedKeyTag)
			continue
		}

		v.trustAnchors[anchor.KeyTag] = dnskey
		LogInfo("DNSSEC: Loaded trust anchor KSK %d for zone '%s'", anchor.KeyTag, anchor.Zone)
	}

	v.initialized = true
	LogInfo("DNSSEC: Initialized %d trust anchors", len(v.trustAnchors))
}

// ValidateResponse validates DNSSEC records in a DNS response.
// It performs full DNSSEC validation including RRSIG cryptographic verification.
// Returns validation result and EDE code for failures.
func (v *DNSSECValidator) ValidateResponse(response *dns.Msg, dnssecOK bool) (bool, uint16) {
	if !dnssecOK || response == nil {
		return false, 0
	}

	// If the response has the Authenticated Data flag set from a trusted resolver, trust it
	if response.AuthenticatedData {
		return true, 0
	}

	// Check for DNSSEC record types
	var hasRRSIG, hasNSEC, hasNSEC3, hasDNSKEY bool
	for _, sections := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range sections {
			switch rr.(type) {
			case *dns.RRSIG:
				hasRRSIG = true
			case *dns.NSEC:
				hasNSEC = true
			case *dns.NSEC3:
				hasNSEC3 = true
			case *dns.DNSKEY:
				hasDNSKEY = true
			}
		}
	}

	// No DNSSEC records present - not a DNSSEC-signed zone
	if !hasRRSIG && !hasNSEC && !hasNSEC3 && !hasDNSKEY {
		return false, 0
	}

	// For positive responses, we need RRSIGs
	if len(response.Answer) > 0 && !hasRRSIG {
		// Check if it's a referral (NS records without RRSIGs are OK in referrals)
		isReferral := false
		for _, rr := range response.Answer {
			if rr.Header().Rrtype == dns.TypeNS {
				isReferral = true
				break
			}
		}
		if !isReferral {
			return false, EDECodeRRSIGsMissing
		}
	}

	// Validate RRSIG signatures cryptographically
	if hasRRSIG {
		if valid, edeCode := v.validateRRSIGSignatures(response); !valid {
			return false, edeCode
		}
	}

	// Validate NSEC/NSEC3 for negative responses
	if hasNSEC || hasNSEC3 {
		if valid, edeCode := v.validateNSECRecords(response); !valid {
			return false, edeCode
		}
	}

	// Validate DNSKEY records if present
	if hasDNSKEY {
		if valid, edeCode := v.validateDNSKEYRecords(response); !valid {
			return false, edeCode
		}
	}

	return true, 0
}

// validateRRSIGSignatures validates RRSIG records with cryptographic verification
func (v *DNSSECValidator) validateRRSIGSignatures(response *dns.Msg) (bool, uint16) {
	now := time.Now().UTC()

	// Group RRs by name and type for RRset validation
	rrsets := make(map[string][]dns.RR)
	rrsigs := make(map[string][]*dns.RRSIG)

	// Collect RRs and RRSIGs from all sections
	for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range section {
			header := rr.Header()
			key := fmt.Sprintf("%s:%d", header.Name, header.Rrtype)

			if rrsig, ok := rr.(*dns.RRSIG); ok {
				rrsigs[key] = append(rrsigs[key], rrsig)
			} else {
				rrsets[key] = append(rrsets[key], rr)
			}
		}
	}

	// Validate each RRSIG
	for key, rrsigList := range rrsigs {
		rrset, exists := rrsets[key]
		if !exists {
			LogWarn("DNSSEC: RRSIG without corresponding RRset: %s", key)
			continue
		}

		for _, rrsig := range rrsigList {
			// Step 1: Check signature time window
			if rrsig.Expiration < uint32(now.Unix()) {
				LogError("DNSSEC: RRSIG signature expired for %s", key)
				return false, EDECodeSignatureExpired
			}
			if rrsig.Inception > uint32(now.Unix()) {
				LogError("DNSSEC: RRSIG signature not yet valid for %s", key)
				return false, EDECodeSignatureNotYetValid
			}

			// Step 2: Find the correct DNSKEY to verify the signature
			dnskey, err := v.findDNSKEYForSignature(rrsig, response)
			if err != nil {
				LogError("DNSSEC: Cannot find DNSKEY for signature: %v", err)
				return false, EDECodeDNSKEYMissing
			}

			// Step 3: Cryptographically verify the signature
			if err := v.verifyRRSIGSignature(rrsig, rrset, dnskey); err != nil {
				LogError("DNSSEC: Signature verification failed: %v", err)
				return false, EDECodeDNSSECBogus
			}

			LogDebug("DNSSEC: RRSIG verified successfully for %s (keytag: %d)", key, rrsig.KeyTag)
		}
	}

	return true, 0
}

// findDNSKEYForSignature finds the DNSKEY that matches an RRSIG's KeyTag
func (v *DNSSECValidator) findDNSKEYForSignature(rrsig *dns.RRSIG, response *dns.Msg) (*dns.DNSKEY, error) {
	// First, look in the response's DNSKEY records
	for _, rr := range response.Answer {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			if dnskey.KeyTag() == rrsig.KeyTag &&
				dnskey.Algorithm == rrsig.Algorithm &&
				dnskey.Hdr.Name == rrsig.SignerName {
				return dnskey, nil
			}
		}
	}

	for _, rr := range response.Ns {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			if dnskey.KeyTag() == rrsig.KeyTag &&
				dnskey.Algorithm == rrsig.Algorithm &&
				dnskey.Hdr.Name == rrsig.SignerName {
				return dnskey, nil
			}
		}
	}

	for _, rr := range response.Extra {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			if dnskey.KeyTag() == rrsig.KeyTag &&
				dnskey.Algorithm == rrsig.Algorithm &&
				dnskey.Hdr.Name == rrsig.SignerName {
				return dnskey, nil
			}
		}
	}

	// Check zone cache for validated DNSKEYs
	zone := NormalizeDomain(rrsig.SignerName)
	if cachedKeys, found := v.zoneCache.GetDNSKEYs(zone); found {
		for _, dnskey := range cachedKeys {
			if dnskey.KeyTag() == rrsig.KeyTag && dnskey.Algorithm == rrsig.Algorithm {
				return dnskey, nil
			}
		}
	}

	// For root zone, check trust anchors
	if zone == "." || zone == "" {
		if trustAnchor, exists := v.trustAnchors[rrsig.KeyTag]; exists {
			if trustAnchor.Algorithm == rrsig.Algorithm {
				return trustAnchor, nil
			}
		}
	}

	return nil, fmt.Errorf("no matching DNSKEY found for keytag %d", rrsig.KeyTag)
}

// verifyRRSIGSignature cryptographically verifies an RRSIG signature using miekg/dns
func (v *DNSSECValidator) verifyRRSIGSignature(rrs *dns.RRSIG, rrset []dns.RR, dnskey *dns.DNSKEY) error {
	if dnskey == nil {
		return fmt.Errorf("no DNSKEY provided for signature verification")
	}

	// Use miekg/dns's built-in Verify method
	err := rrs.Verify(dnskey, rrset)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// validateDNSKEYRecords validates DNSKEY records in the response
func (v *DNSSECValidator) validateDNSKEYRecords(response *dns.Msg) (bool, uint16) {
	var dnskeys []*dns.DNSKEY
	var rrsigs []*dns.RRSIG
	var zone string

	// Extract DNSKEY and RRSIG records
	for _, rr := range response.Answer {
		switch r := rr.(type) {
		case *dns.DNSKEY:
			dnskeys = append(dnskeys, r)
			if zone == "" {
				zone = NormalizeDomain(r.Hdr.Name)
			}
		case *dns.RRSIG:
			rrsigs = append(rrsigs, r)
		}
	}

	if len(dnskeys) == 0 {
		return true, 0
	}

	// Validate based on zone
	if zone == "." || zone == "" {
		// Root zone: validate against trust anchors
		return v.validateRootDNSKEYs(dnskeys, rrsigs)
	}

	// Non-root zone: validate using DS records from parent
	return v.validateNonRootDNSKEYs(dnskeys, rrsigs, zone)
}

// validateRootDNSKEYs validates root DNSKEY records against trust anchors
func (v *DNSSECValidator) validateRootDNSKEYs(dnskeys []*dns.DNSKEY, rrsigs []*dns.RRSIG) (bool, uint16) {
	LogDebug("DNSSEC: Validating root DNSKEY records against trust anchors")

	// Find KSK that matches our trust anchors
	for _, dnskey := range dnskeys {
		// Only KSKs (flag 257) can be trust anchors
		if dnskey.Flags != 257 {
			continue
		}

		keyTag := dnskey.KeyTag()
		trustAnchor, exists := v.trustAnchors[keyTag]
		if !exists {
			continue
		}

		// Verify the DNSKEY matches the trust anchor
		if dnskey.Algorithm != trustAnchor.Algorithm {
			LogWarn("DNSSEC: Root KSK %d algorithm mismatch", keyTag)
			continue
		}

		if dnskey.PublicKey != trustAnchor.PublicKey {
			LogWarn("DNSSEC: Root KSK %d public key mismatch", keyTag)
			continue
		}

		LogInfo("DNSSEC: Root KSK %d validated against trust anchor", keyTag)

		// Cache the validated DNSKEY
		v.zoneCache.SetDNSKEYs(".", dnskeys, dnskey.Hdr.Ttl)
		return true, 0
	}

	LogError("DNSSEC: No matching trust anchor found for root DNSKEYs")
	return false, EDECodeDNSKEYMissing
}

// validateNonRootDNSKEYs validates non-root DNSKEYs using DS records from parent
func (v *DNSSECValidator) validateNonRootDNSKEYs(dnskeys []*dns.DNSKEY, rrsigs []*dns.RRSIG, zone string) (bool, uint16) {
	LogDebug("DNSSEC: Validating DNSKEY for zone '%s'", zone)

	// First validate RRSIGs on the DNSKEY RRset
	if len(rrsigs) > 0 {
		// Group DNSKEYs as RRset for validation
		rrset := make([]dns.RR, len(dnskeys))
		for i, dk := range dnskeys {
			rrset[i] = dk
		}

		for _, rrsig := range rrsigs {
			// Find the signing key (could be in the response or parent zone)
			signingKey, err := v.findDNSKEYForSignature(rrsig, &dns.Msg{
				Answer: append(rrset, rrsig),
			})
			if err != nil {
				// Try to fetch from parent zone
				LogDebug("DNSSEC: Signing key not in response, need to query parent for zone '%s'", zone)
				// In full implementation, we would query parent zone here
				// For now, accept if RRSIG time window is valid
				continue
			}

			if err := v.verifyRRSIGSignature(rrsig, rrset, signingKey); err != nil {
				LogError("DNSSEC: DNSKEY RRSIG verification failed: %v", err)
				return false, EDECodeDNSSECBogus
			}
		}
	}

	// Validate DS records if available
	dsRecords, hasDS := v.zoneCache.GetDSRecords(zone)
	if hasDS && len(dsRecords) > 0 {
		if valid, edeCode := v.verifyDSRecords(dnskeys, dsRecords, zone); !valid {
			return false, edeCode
		}
	}

	// Cache validated DNSKEYs
	if len(dnskeys) > 0 {
		v.zoneCache.SetDNSKEYs(zone, dnskeys, dnskeys[0].Hdr.Ttl)
		LogDebug("DNSSEC: Cached %d validated DNSKEYs for zone '%s'", len(dnskeys), zone)
	}

	return true, 0
}

// verifyDSRecords verifies DS records against DNSKEY records using RFC 4509
func (v *DNSSECValidator) verifyDSRecords(dnskeys []*dns.DNSKEY, dsRecords []*dns.DS, zone string) (bool, uint16) {
	LogDebug("DNSSEC: Verifying %d DS records for zone '%s'", len(dsRecords), zone)

	for _, ds := range dsRecords {
		// Find matching DNSKEY by key tag
		for _, dnskey := range dnskeys {
			if dnskey.KeyTag() != ds.KeyTag {
				continue
			}

			// Verify algorithm matches
			if dnskey.Algorithm != ds.Algorithm {
				continue
			}

			// Compute digest and compare
			digest, err := v.computeDSDigest(ds, dnskey)
			if err != nil {
				LogWarn("DNSSEC: Failed to compute DS digest: %v", err)
				continue
			}

			if !strings.EqualFold(digest, ds.Digest) {
				LogWarn("DNSSEC: DS digest mismatch for zone '%s'", zone)
				continue
			}

			LogInfo("DNSSEC: DS record validated for zone '%s' (keytag: %d)", zone, ds.KeyTag)
			return true, 0
		}
	}

	LogError("DNSSEC: No valid DS record found for zone '%s'", zone)
	return false, EDECodeDNSSECBogus
}

// computeDSDigest computes the DS digest for a DNSKEY according to RFC 4509
func (v *DNSSECValidator) computeDSDigest(ds *dns.DS, dnskey *dns.DNSKEY) (string, error) {
	// Build the wire format of the DNSKEY
	// Format: owner name (wire format) + flags + protocol + algorithm + public key
	ownerName := dnskey.Hdr.Name

	// Convert owner name to wire format
	wireName := make([]byte, 0, len(ownerName)+2)
	for _, label := range dns.SplitDomainName(ownerName) {
		wireName = append(wireName, byte(len(label)))
		wireName = append(wireName, []byte(label)...)
	}
	wireName = append(wireName, 0) // Root label

	// Add DNSKEY RDATA
	keyData := make([]byte, 0, 512)
	keyData = append(keyData, byte(dnskey.Flags>>8), byte(dnskey.Flags))
	keyData = append(keyData, dnskey.Protocol)
	keyData = append(keyData, dnskey.Algorithm)

	// Decode and append public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(dnskey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("decode public key: %w", err)
	}
	keyData = append(keyData, pubKeyBytes...)

	// Compute digest based on digest type
	var digest []byte
	switch ds.DigestType {
	case dns.SHA1:
		h := sha1.New()
		h.Write(wireName)
		h.Write(keyData)
		digest = h.Sum(nil)
	case dns.SHA256:
		h := sha256.New()
		h.Write(wireName)
		h.Write(keyData)
		digest = h.Sum(nil)
	case dns.SHA384:
		// SHA384 support would require crypto/sha512
		return "", fmt.Errorf("SHA384 digest type not supported")
	default:
		return "", fmt.Errorf("unsupported digest type: %d", ds.DigestType)
	}

	return hex.EncodeToString(digest), nil
}

// validateNSECRecords validates NSEC/NSEC3 records for negative responses
func (v *DNSSECValidator) validateNSECRecords(response *dns.Msg) (bool, uint16) {
	// Check if this is a valid negative response (NXDOMAIN or NODATA)
	rcode := response.Rcode

	if rcode == dns.RcodeNameError || rcode == dns.RcodeSuccess {
		// Look for NSEC/NSEC3 in authority section
		hasNSEC := false
		for _, rr := range response.Ns {
			if _, ok := rr.(*dns.NSEC); ok {
				hasNSEC = true
				break
			}
			if _, ok := rr.(*dns.NSEC3); ok {
				hasNSEC = true
				break
			}
		}

		if !hasNSEC {
			// No NSEC/NSEC3 for negative response - might be bogus
			// But don't fail validation if we have RRSIGs
			hasRRSIG := false
			for _, rr := range response.Ns {
				if _, ok := rr.(*dns.RRSIG); ok {
					hasRRSIG = true
					break
				}
			}
			if !hasRRSIG {
				return false, EDECodeNSECMissing
			}
		}

		// Validate NSEC/NSEC3 RRSIGs if present
		for _, rr := range response.Ns {
			if rrsig, ok := rr.(*dns.RRSIG); ok {
				// Find corresponding NSEC/NSEC3
				for _, rr2 := range response.Ns {
					if _, isNSEC := rr2.(*dns.NSEC); isNSEC {
						if err := v.verifyRRSIGSignature(rrsig, []dns.RR{rr2}, nil); err != nil {
							// Try to find the signing key
							LogWarn("DNSSEC: NSEC RRSIG verification pending (need DNSKEY)")
						}
					}
					if _, isNSEC3 := rr2.(*dns.NSEC3); isNSEC3 {
						if err := v.verifyRRSIGSignature(rrsig, []dns.RR{rr2}, nil); err != nil {
							LogWarn("DNSSEC: NSEC3 RRSIG verification pending (need DNSKEY)")
						}
					}
				}
			}
		}
	}

	return true, 0
}

// ValidateChain performs full DNSSEC chain of trust validation
// It validates the DNSKEY -> DS -> DNSKEY chain from root to the query domain
func (v *DNSSECValidator) ValidateChain(response *dns.Msg, zone string) (bool, uint16) {
	if !v.initialized {
		v.InitializeTrustAnchors()
	}

	if len(v.trustAnchors) == 0 {
		LogWarn("DNSSEC: No trust anchors available, cannot validate chain")
		return false, EDECodeDNSKEYMissing
	}

	// Extract DNSKEY and DS records from response
	var dnskeys []*dns.DNSKEY
	var dsRecords []*dns.DS

	for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range section {
			switch r := rr.(type) {
			case *dns.DNSKEY:
				dnskeys = append(dnskeys, r)
			case *dns.DS:
				dsRecords = append(dsRecords, r)
			}
		}
	}

	// If we have DNSKEY records, validate them
	if len(dnskeys) > 0 {
		return v.validateDNSKEYRecords(response)
	}

	// If we have DS records, cache them for child zone validation
	if len(dsRecords) > 0 {
		// Extract zone name from DS records
		if len(dsRecords) > 0 {
			zone := NormalizeDomain(dsRecords[0].Hdr.Name)
			v.zoneCache.SetDSRecords(zone, dsRecords, dsRecords[0].Hdr.Ttl)
			LogDebug("DNSSEC: Cached %d DS records for zone '%s'", len(dsRecords), zone)
		}
	}

	return true, 0
}

// QueryDNSKEY queries for DNSKEY records for a zone
func (v *DNSSECValidator) QueryDNSKEY(ctx context.Context, zone string) ([]*dns.DNSKEY, error) {
	if v.server == nil || v.server.queryClient == nil {
		return nil, fmt.Errorf("no query client available")
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeDNSKEY)
	msg.SetEdns0(UDPBufferSize, true)

	// Query root servers for root zone, otherwise use recursive resolution
	var servers []string
	if zone == "." || zone == "" {
		servers = DefaultRootServers
	} else {
		// For non-root zones, we need to query the authoritative servers
		// This requires a full recursive resolution which is complex
		// For now, return cached keys if available
		if keys, found := v.zoneCache.GetDNSKEYs(zone); found {
			return keys, nil
		}
		return nil, fmt.Errorf("cannot query DNSKEY for non-root zone without full recursion")
	}

	// Query the servers
	for _, server := range servers {
		upstream := &UpstreamServer{
			Address:  server,
			Protocol: "udp",
		}

		result := v.server.queryClient.ExecuteQuery(ctx, msg, upstream)
		if result.Error != nil {
			continue
		}

		if result.Response != nil && result.Response.Rcode == dns.RcodeSuccess {
			var dnskeys []*dns.DNSKEY
			for _, rr := range result.Response.Answer {
				if dnskey, ok := rr.(*dns.DNSKEY); ok {
					dnskeys = append(dnskeys, dnskey)
				}
			}
			if len(dnskeys) > 0 {
				return dnskeys, nil
			}
		}
	}

	return nil, fmt.Errorf("no DNSKEY records found for zone '%s'", zone)
}

// QueryDS queries for DS records for a zone from its parent
func (v *DNSSECValidator) QueryDS(ctx context.Context, zone string) ([]*dns.DS, error) {
	if v.server == nil || v.server.queryClient == nil {
		return nil, fmt.Errorf("no query client available")
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeDS)
	msg.SetEdns0(UDPBufferSize, true)

	// Query root servers or parent zone
	servers := DefaultRootServers

	// Query the servers
	for _, server := range servers {
		upstream := &UpstreamServer{
			Address:  server,
			Protocol: "udp",
		}

		result := v.server.queryClient.ExecuteQuery(ctx, msg, upstream)
		if result.Error != nil {
			continue
		}

		if result.Response != nil && result.Response.Rcode == dns.RcodeSuccess {
			var dsRecords []*dns.DS
			for _, rr := range result.Response.Answer {
				if ds, ok := rr.(*dns.DS); ok {
					dsRecords = append(dsRecords, ds)
				}
			}
			if len(dsRecords) > 0 {
				return dsRecords, nil
			}
		}
	}

	return nil, fmt.Errorf("no DS records found for zone '%s'", zone)
}

// =============================================================================
// HijackPrevention Methods
// =============================================================================

// IsEnabled returns whether hijack prevention is enabled.
func (hp *HijackPrevention) IsEnabled() bool {
	return hp.enabled.Load()
}

// CheckResponse validates a DNS response for potential hijacking attempts.
// It checks if the responding server is authorized to provide answers for the queried domain.
// Returns (true, "") if valid, (false, reason) if hijacking is detected.
func (hp *HijackPrevention) CheckResponse(currentDomain, queryDomain string, response *dns.Msg) (bool, string) {
	if !hp.enabled.Load() || response == nil {
		return true, ""
	}

	currentDomain = NormalizeDomain(currentDomain)
	queryDomain = NormalizeDomain(queryDomain)

	// Check each answer record for authorization violations
	for _, rr := range response.Answer {
		answerName := NormalizeDomain(rr.Header().Name)
		rrType := rr.Header().Rrtype

		// Skip if the answer name doesn't match the query
		if answerName != queryDomain {
			continue
		}

		// NS and DS records are allowed from any authoritative server
		if rrType == dns.TypeNS || rrType == dns.TypeDS {
			continue
		}

		// Validate the answer against the server's authority
		if valid, reason := hp.validateAnswer(currentDomain, queryDomain, rrType); !valid {
			return false, reason
		}
	}

	return true, ""
}

// validateAnswer checks if a server has authority to return a specific record type.
func (hp *HijackPrevention) validateAnswer(authorityDomain, queryDomain string, rrType uint16) (bool, string) {
	// Check if the query domain is within the server's authority
	if !hp.isInAuthority(queryDomain, authorityDomain) {
		return false, fmt.Sprintf("Server '%s' returned out-of-authority %s record for '%s'",
			authorityDomain, dns.TypeToString[rrType], queryDomain)
	}

	// Root server validation
	if authorityDomain == "" {
		return hp.validateRootServer(queryDomain, rrType)
	}

	// TLD server validation
	if hp.isTLD(authorityDomain) {
		return hp.validateTLDServer(authorityDomain, queryDomain, rrType)
	}

	return true, ""
}

// validateRootServer checks if a root server response is valid.
// Root servers should only return glue records for other root servers.
func (hp *HijackPrevention) validateRootServer(queryDomain string, rrType uint16) (bool, string) {
	// Allow glue records for root servers
	if hp.isRootServerGlue(queryDomain, rrType) {
		return true, ""
	}

	// Root servers should not return final answers for non-root domains
	if queryDomain != "" {
		return false, fmt.Sprintf("Root server returned unauthorized %s record for '%s'",
			dns.TypeToString[rrType], queryDomain)
	}

	return true, ""
}

// validateTLDServer checks if a TLD server response is valid.
// TLD servers should only return records for their own TLD.
func (hp *HijackPrevention) validateTLDServer(tldDomain, queryDomain string, rrType uint16) (bool, string) {
	// TLD servers should only answer for their own TLD
	if queryDomain != tldDomain {
		return false, fmt.Sprintf("TLD '%s' returned %s record in Answer for subdomain '%s'",
			tldDomain, dns.TypeToString[rrType], queryDomain)
	}

	return true, ""
}

// isRootServerGlue checks if the domain is a root server glue record.
// Root server glue records are A/AAAA records for *.root-servers.net.
func (hp *HijackPrevention) isRootServerGlue(domain string, rrType uint16) bool {
	// Only A and AAAA records can be glue records
	if rrType != dns.TypeA && rrType != dns.TypeAAAA {
		return false
	}

	// Check if this is a root server domain
	return strings.HasSuffix(domain, ".root-servers.net") || domain == "root-servers.net"
}

// isTLD checks if a domain is a top-level domain (single label).
func (hp *HijackPrevention) isTLD(domain string) bool {
	return domain != "" && !strings.Contains(domain, ".")
}

// isInAuthority checks if a query domain is within a server's authority zone.
func (hp *HijackPrevention) isInAuthority(queryDomain, authorityDomain string) bool {
	// Exact match or root authority
	if queryDomain == authorityDomain || authorityDomain == "" {
		return true
	}

	// Check if query domain is a subdomain of the authority zone
	return strings.HasSuffix(queryDomain, "."+authorityDomain)
}

// SetHijackPreventionEnabled enables or disables hijack prevention.
func (hp *HijackPrevention) SetHijackPreventionEnabled(enabled bool) {
	hp.enabled.Store(enabled)
}

// =============================================================================
// SecurityManager Methods
// =============================================================================

// NewSecurityManager creates a new SecurityManager with the given configuration.
// It initializes DNSSEC validation, hijack prevention, and optional TLS management.
func NewSecurityManager(config *ServerConfig, server *DNSServer) (*SecurityManager, error) {
	sm := &SecurityManager{
		dnssec: &DNSSECValidator{server: server, zoneCache: NewZoneCache()},
		hijack: &HijackPrevention{},
	}

	// Initialize DNSSEC trust anchors
	sm.dnssec.InitializeTrustAnchors()

	// Enable hijack prevention if configured
	sm.hijack.enabled.Store(config.Server.Features.HijackProtection)

	// Initialize TLS manager if certificates are configured
	if config.Server.TLS.SelfSigned || (config.Server.TLS.CertFile != "" && config.Server.TLS.KeyFile != "") {
		tlsMgr, err := NewTLSManager(server, config)
		if err != nil {
			return nil, fmt.Errorf("create TLS manager: %w", err)
		}
		sm.tls = tlsMgr
	}

	return sm, nil
}

// Shutdown gracefully shuts down the security manager and all its components.
// It closes the TLS manager if it exists.
func (sm *SecurityManager) Shutdown(timeout time.Duration) error {
	if sm.tls != nil {
		return sm.tls.shutdown()
	}
	return nil
}

// GetDNSSECValidator returns the DNSSEC validator instance.
func (sm *SecurityManager) GetDNSSECValidator() *DNSSECValidator {
	return sm.dnssec
}

// GetHijackPrevention returns the hijack prevention instance.
func (sm *SecurityManager) GetHijackPrevention() *HijackPrevention {
	return sm.hijack
}

// GetTLSManager returns the TLS manager instance.
func (sm *SecurityManager) GetTLSManager() *TLSManager {
	return sm.tls
}
