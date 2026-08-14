package resolver

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/resolver/dnssec"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// stripCrossZoneRecords removes answer records whose RRSIG signer name is
// from a different zone hierarchy than the given zone. These records need
// independent DNSSEC validation via CNAME chain following.  RRSIG records
// covering kept RRsets are kept — RFC 4035 §3.1.1: a signed RRset placed in
// the Answer section MUST be accompanied by its RRSIGs (a DO=1 client
// cannot validate without them).  RRSIGs covering stripped RRsets are
// dropped with them.
//
// Note: only RRSIGs located in the Answer section are emitted.  Upstream
// servers that place an answer RRset's signatures in the Additional section
// (non-standard — RFC 4035 §3.1.1 keeps RRset and RRSIGs together) keep
// them there; callers preserve response.Extra separately, so the signatures
// still reach DO=1 clients.
func stripCrossZoneRecords(answer, extra []dns.RR, zone string) []dns.RR {
	fqZone := dnsutil.Fqdn(zone)
	if fqZone == "." {
		return answer
	}
	allSigs := dnssec.CollectRRSIGs(answer, extra)

	// Canonicalize each distinct owner name once — dnsutil.Canonical
	// allocates (strings.Map), and the same name is keyed repeatedly across
	// the two passes below.
	canonName := make(map[string]string, len(answer))
	canon := func(name string) string {
		if c, ok := canonName[name]; ok {
			return c
		}
		c := dnsutil.Canonical(name)
		canonName[name] = c
		return c
	}

	// Pass 1: decide which data RRsets survive the zone filter.  RRSIG
	// records are skipped here — their fate is decided by the RRset they
	// cover in pass 2.
	keepRRset := make(map[string]bool, len(answer))
	for _, r := range answer {
		if r == nil {
			continue
		}
		if _, isSig := r.(*dns.RRSIG); isSig {
			continue
		}
		h := r.Header()
		sigs := dnssec.FindRRSIGs(allSigs, h.Name, dns.RRToType(r))
		if len(sigs) == 0 {
			// In a signed response (some RRSIGs present), an unsigned RRset
			// is anomalous and must not be served as authenticated data.
			// Fully unsigned responses (unsigned zones) are left untouched.
			if len(allSigs) > 0 {
				log.Debugf("SECURITY: dropping unsigned record %s/%s in signed %s answer", h.Name, dns.TypeToString[dns.RRToType(r)], zone)
				continue
			}
			keepRRset[rrsetKey(canon(h.Name), dns.RRToType(r))] = true
			continue
		}
		inZone := false
		for _, sig := range sigs {
			sigZone := dnsutil.Fqdn(sig.SignerName)
			// A signer equal to the zone apex is in-zone; records signed by
			// the zone itself were being stripped as cross-zone.
			if dns.EqualName(sigZone, fqZone) || dnsutil.IsBelow(fqZone, sigZone) {
				inZone = true
				break
			}
		}
		if inZone {
			keepRRset[rrsetKey(canon(h.Name), dns.RRToType(r))] = true
		} else {
			log.Debugf("SECURITY: stripping cross-zone record %s/%s from %s answer", h.Name, dns.TypeToString[dns.RRToType(r)], zone)
		}
	}

	// Pass 2: emit the kept data records in order, together with the
	// RRSIGs covering them.
	result := make([]dns.RR, 0, len(answer))
	for _, r := range answer {
		if r == nil {
			continue
		}
		if sig, ok := r.(*dns.RRSIG); ok {
			if keepRRset[rrsetKey(canon(sig.Header().Name), sig.TypeCovered)] {
				result = append(result, r)
			}
			continue
		}
		if keepRRset[rrsetKey(canon(r.Header().Name), dns.RRToType(r))] {
			result = append(result, r)
		}
	}
	return result
}

// rrsetKey builds a collision-free key for the keepRRset map: the canonical
// (lowercased) owner name and the numeric RR type.  Unknown types (RFC 3597,
// e.g. TYPE1234) have no entry in dns.TypeToString and would otherwise
// collapse distinct RRsets into a single "name/" key; raw owner names would
// not match RRSIGs that differ from the data record only in case.  Callers
// must pass the name already canonicalized (once per response).
func rrsetKey(name string, typ uint16) string {
	return name + "/" + strconv.Itoa(int(typ))
}

func (r *Recursive) getZoneCutSigner(response *dns.Msg, currentDomain string) string {
	if response == nil || len(response.Answer) == 0 {
		return ""
	}

	fqCurrent := dnsutil.Fqdn(currentDomain)
	if fqCurrent == "." {
		return ""
	}

	rrsigs := dnssec.CollectRRSIGs(response.Answer, response.Extra)
	var best string
	for _, rrsig := range rrsigs {
		if rrsig == nil {
			continue
		}
		signerName := dnsutil.Fqdn(rrsig.SignerName)
		if !dns.EqualName(signerName, fqCurrent) && dnsutil.IsBelow(fqCurrent, signerName) {
			// Select the closest (deepest) ancestor signer: in a
			// mixed-signer answer (e.g. a CNAME chain across zones), the
			// first match may not be the actual zone cut for this name.
			if best == "" || dnsutil.Labels(signerName) > dnsutil.Labels(best) {
				best = signerName
			}
		}
	}

	return best
}

func (r *Recursive) resolveZoneCut(ctx context.Context, response *dns.Msg, nameservers []string, question Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, chain *dnssecChain) (bool, error) {
	crypto := r.resolver.validator.Crypto

	childZone := r.getZoneCutSigner(response, currentDomain)
	if childZone == "" {
		return false, errors.New("could not determine child zone name from RRSIG signer")
	}

	if len(chain.childDS) == 0 && len(chain.zoneDNSKEYs) == 0 {
		// Unsigned delegation: no DS at the cut means no verifiable keys —
		// a DNSKEY fetch can only return empty.  (Signed zones keep the
		// fetch; a signer-mismatch RRSIG can only come from a signed zone.)
		return false, errors.New("unsigned delegation — no DNSKEYs to verify zone cut")
	}
	if len(chain.zoneDNSKEYs) == 0 {
		r.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
	}
	parentKeys := chain.zoneDNSKEYs
	if len(parentKeys) == 0 {
		return false, fmt.Errorf("no parent DNSKEYs available to verify DS for %s", childZone)
	}

	// The DS RRset must come from the PARENT side of the zone cut: the
	// parent's servers are authoritative for it. Never ask the child's
	// servers — an attacker-controlled child could answer NODATA and
	// downgrade a signed delegation to insecure.
	dsQuestion := Question{Name: dnsutil.Fqdn(childZone), Qtype: dns.TypeDS, Qclass: dns.ClassINET}
	dsResp, _, dsErr := r.queryNameserversConcurrent(ctx, nameservers, dsQuestion, ecs, forceTCP, currentDomain, r.resolver.validator.Poisonguard)
	if dsErr != nil {
		return false, fmt.Errorf("DS query for %s failed: %w", childZone, dsErr)
	}
	defer pool.DefaultMessage.Put(dsResp)

	var verifiedDS []*dns.DS
	dsRecords := dnssec.FindDS(dsResp.Answer)
	dsRecords = append(dsRecords, dnssec.FindDS(dsResp.Ns)...)
	if len(dsRecords) == 0 {
		// A signed parent must prove the absence of DS with an
		// authenticated NSEC/NSEC3 denial; a bare NODATA is not proof.
		noDS, dsRaced := r.verifyNoDSInParent(ctx, nameservers, childZone, currentDomain, chain)
		switch {
		case noDS:
			chain.childDS = nil
			chain.dsPresentButUnverified = false
			return false, nil
		case dsRaced:
			// The DS query raced the delegation: verifyNoDSInParent
			// verified the DS inline and recorded it in chain.childDS —
			// continue the zone cut with the verified DS below.  A failed
			// inline verification left dsPresentButUnverified set; report
			// the raced outcome explicitly instead of the generic RRSIG
			// verification error below.
			verifiedDS = chain.childDS
			if chain.dsPresentButUnverified {
				return false, fmt.Errorf("raced DS for %s could not be verified — delegation unverifiable", childZone)
			}
		default:
			return false, fmt.Errorf("no authenticated denial for missing DS at %s (signed parent)", childZone)
		}
	} else {
		allSigs := dnssec.CollectRRSIGs(dsResp.Answer, dsResp.Ns, dsResp.Extra)
		dsRRSIGs := dnssec.FindRRSIGs(allSigs, dnsutil.Fqdn(childZone), dns.TypeDS)
		if len(dsRRSIGs) == 0 {
			return false, fmt.Errorf("no RRSIG for DS records of %s", childZone)
		}

		rrset := make([]dns.RR, len(dsRecords))
		for i, ds := range dsRecords {
			rrset[i] = ds
		}

		for _, rrsig := range dsRRSIGs {
			for _, key := range parentKeys {
				if key.KeyTag() != rrsig.KeyTag {
					continue
				}
				if err := crypto.VerifyRRset(rrset, rrsig, key); err == nil {
					verifiedDS = dsRecords
					log.Debugf("SECURITY: zone cut — verified DS for %s (key_tag=%d)", childZone, key.KeyTag())
					break
				}
			}
			if len(verifiedDS) > 0 {
				break
			}
		}
	}
	if len(verifiedDS) == 0 {
		return false, fmt.Errorf("DS RRSIG verification failed for %s", childZone)
	}

	chain.childDS = verifiedDS

	// The child DNSKEY RRset must come from the CHILD side of the zone cut.
	// Querying it from the parent's servers returns a referral (no answer);
	// querying the child is also required so an attacker-controlled parent
	// cannot substitute its own keys.
	childServers := r.resolveChildNameservers(ctx, nameservers, childZone, currentDomain, question.Name, ecs, forceTCP, dsResp)
	if len(childServers) == 0 {
		return false, fmt.Errorf("could not resolve nameservers for child zone %s", childZone)
	}

	dnskeyQuestion := Question{Name: dnsutil.Fqdn(childZone), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, _, dnskeyErr := r.queryNameserversConcurrent(ctx, childServers, dnskeyQuestion, ecs, forceTCP, childZone, r.resolver.validator.Poisonguard)
	if dnskeyErr != nil {
		return false, fmt.Errorf("DNSKEY query for %s failed: %w", childZone, dnskeyErr)
	}
	defer pool.DefaultMessage.Put(dnskeyResp)

	dnskeyRecords := dnssec.FindDNSKEYs(dnskeyResp.Answer)
	if len(dnskeyRecords) == 0 {
		return false, fmt.Errorf("no DNSKEY records found for %s", childZone)
	}

	allKeySigs := dnssec.CollectRRSIGs(dnskeyResp.Answer, dnskeyResp.Ns, dnskeyResp.Extra)
	dnskeyRRSIGs := dnssec.FindRRSIGs(allKeySigs, dnsutil.Fqdn(childZone), dns.TypeDNSKEY)

	// The DS match proves only ONE key; the matched key must additionally
	// sign the ENTIRE RRset (RFC 4035 §5.2) — otherwise an attacker who can
	// inject the DNSKEY response could append a rogue key and validate a
	// forged answer with it (CryptoValidator.IsResponseValid accepts any
	// key in the slice).  verifyDNSKEYWithDS enforces both.
	matchedKey, dsMatchErr := verifyDNSKEYWithDS(crypto, verifiedDS, dnskeyRecords, dnskeyRRSIGs)
	if dsMatchErr != nil {
		log.Debugf("SECURITY: zone cut — DS→DNSKEY verification failed for %s: %v", childZone, dsMatchErr)
		chain.lastEDECode = dns.ExtendedErrorDNSBogus
		return false, nil
	}

	log.Debugf("SECURITY: zone cut — verified DNSKEY for %s (key_tag=%d)", childZone, matchedKey.KeyTag())

	crypto.CacheZoneKeys(childZone, dnskeyRecords)

	validated, valErr := crypto.IsResponseValid(response, childZone, dnskeyRecords)
	if valErr != nil {
		log.Debugf("SECURITY: zone cut — answer RRSIG verification failed for %s: %v", question.Name, valErr)
		chain.lastEDECode = dns.ExtendedErrorDNSBogus
		return false, nil
	}
	if !validated {
		chain.lastEDECode = dns.ExtendedErrorRRSIGsMissing
		return false, nil
	}
	return true, nil
}

// resolveChildNameservers resolves the authoritative server addresses for the
// child zone across the zone cut. The NS RRset is fetched from the parent
// side (which is authoritative for the delegation), then the NS names are
// resolved to addresses like any other delegation level.
//
// When mergedResp is non-nil and carries NS records, they are extracted
// directly.  Otherwise a separate NS query is issued.  The caller owns
// mergedResp and its pool lifetime — it is never Put here.
func (r *Recursive) resolveChildNameservers(ctx context.Context, nameservers []string, childZone, currentDomain, qname string, ecs *edns.ECSOption, forceTCP bool, mergedResp *dns.Msg) []string {
	nsRecords := extractChildNS(childZone, mergedResp)
	if nsRecords == nil {
		// Fallback: no NS in the merged response — issue a standalone NS query.
		nsQuestion := Question{Name: dnsutil.Fqdn(childZone), Qtype: dns.TypeNS, Qclass: dns.ClassINET}
		resp, _, err := r.queryNameserversConcurrent(ctx, nameservers, nsQuestion, ecs, forceTCP, currentDomain, r.resolver.validator.Poisonguard) // _ = verdict: poison already gated per-response in queryNameserversConcurrent
		if err != nil || resp == nil {
			log.Debugf("SECURITY: NS query for child zone %s failed: %v", childZone, err)
			return nil
		}
		defer pool.DefaultMessage.Put(resp)
		nsRecords = extractChildNS(childZone, resp)
	}
	if len(nsRecords) == 0 {
		log.Debugf("SECURITY: no NS records for child zone %s in parent referral", childZone)
		return nil
	}

	return r.resolveNSAddressesConcurrent(ctx, nsRecords, qname, 0, forceTCP)
}

// extractChildNS returns the NS records for childZone found in resp's
// Authority or Answer sections (an empty slice means "not present").
func extractChildNS(childZone string, resp *dns.Msg) []*dns.NS {
	if resp == nil {
		return nil
	}
	var nsRecords []*dns.NS
	// When the same server hosts both parent and child zones, the delegation
	// NS records may appear in the Answer section instead of Authority.
	for _, rrec := range append(resp.Ns, resp.Answer...) {
		if ns, ok := rrec.(*dns.NS); ok && dns.EqualName(dnsutil.Fqdn(rrec.Header().Name), dnsutil.Fqdn(childZone)) {
			nsRecords = append(nsRecords, ns)
		}
	}
	return nsRecords
}

func (r *Recursive) isZoneCut(response *dns.Msg, currentDomain string) bool {
	return r.getZoneCutSigner(response, currentDomain) != ""
}
