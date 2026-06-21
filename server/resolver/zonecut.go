package resolver

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/security"
)

func (rr *Recursive) getZoneCutSigner(response *dns.Msg, currentDomain string) string {
	if response == nil || len(response.Answer) == 0 {
		return ""
	}

	normalizedCurrent := dnsutil.NormalizeDomain(currentDomain)
	if normalizedCurrent == "" {
		return ""
	}

	rrsigs := security.CollectRRSIGs(response.Answer, response.Extra)
	for _, rrsig := range rrsigs {
		if rrsig == nil {
			continue
		}
		signerName := dnsutil.NormalizeDomain(rrsig.SignerName)
		if signerName != normalizedCurrent &&
			strings.HasSuffix(signerName, "."+normalizedCurrent) {
			return signerName
		}
	}

	return ""
}
func (rr *Recursive) resolveZoneCut(ctx context.Context, response *dns.Msg, nameservers []string, question dns.Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, chain *dnssecChain) (bool, error) {
	crypto := rr.resolver.validator.Crypto

	// Extract the child zone name from the RRSIG signer
	childZone := rr.getZoneCutSigner(response, currentDomain)
	if childZone == "" {
		return false, fmt.Errorf("could not determine child zone name from RRSIG signer")
	}

	// Ensure we have verified DNSKEYs for the parent zone
	if len(chain.zoneDNSKEYs) == 0 {
		rr.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
	}
	parentKeys := chain.zoneDNSKEYs
	if len(parentKeys) == 0 {
		parentKeys = chain.parentDNSKEYs
	}
	if len(parentKeys) == 0 {
		return false, fmt.Errorf("no parent DNSKEYs available to verify DS for %s", childZone)
	}

	// Query for the child zone's DS records from the parent zone.
	// These are used to verify the child zone's DNSKEYs.
	dsQuestion := dns.Question{Name: dns.Fqdn(childZone), Qtype: dns.TypeDS, Qclass: dns.ClassINET}
	dsResp, dsErr := rr.queryNameserversConcurrent(ctx, nameservers, dsQuestion, ecs, forceTCP)
	if dsErr != nil {
		return false, fmt.Errorf("DS query for %s failed: %w", childZone, dsErr)
	}
	defer pool.DefaultMessagePool.Put(dsResp)

	dsRecords := security.FindDS(dsResp.Answer)
	dsRecords = append(dsRecords, security.FindDS(dsResp.Ns)...)
	if len(dsRecords) == 0 {
		return false, fmt.Errorf("no DS records found for %s", childZone)
	}

	// Verify DS RRSIGs against the parent zone's DNSKEYs
	allSigs := security.CollectRRSIGs(dsResp.Answer, dsResp.Ns, dsResp.Extra)
	dsRRSIGs := security.FindRRSIGs(allSigs, dns.Fqdn(childZone), dns.TypeDS)
	if len(dsRRSIGs) == 0 {
		return false, fmt.Errorf("no RRSIG for DS records of %s", childZone)
	}

	rrset := make([]dns.RR, len(dsRecords))
	for i, ds := range dsRecords {
		rrset[i] = ds
	}

	var verifiedDS []*dns.DS
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
	if len(verifiedDS) == 0 {
		return false, fmt.Errorf("DS RRSIG verification failed for %s", childZone)
	}

	// Update the trust chain with the verified DS records so the caller's
	// DNSSECEnforce check uses the correct child zone DS rather than stale
	// DS records from a prior delegation step.
	chain.childDS = verifiedDS

	// Query for the child zone's DNSKEY records
	dnskeyQuestion := dns.Question{Name: dns.Fqdn(childZone), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, dnskeyErr := rr.queryNameserversConcurrent(ctx, nameservers, dnskeyQuestion, ecs, forceTCP)
	if dnskeyErr != nil {
		return false, fmt.Errorf("DNSKEY query for %s failed: %w", childZone, dnskeyErr)
	}
	defer pool.DefaultMessagePool.Put(dnskeyResp)

	dnskeyRecords := security.FindDNSKEYs(dnskeyResp.Answer)
	if len(dnskeyRecords) == 0 {
		return false, fmt.Errorf("no DNSKEY records found for %s", childZone)
	}

	// Verify child DNSKEYs against the verified DS records
	matchedKey, dsMatchErr := crypto.VerifyDelegationDS(verifiedDS, dnskeyRecords)
	if dsMatchErr != nil {
		log.Debugf("SECURITY: zone cut — DS→DNSKEY mismatch for %s: %v", childZone, dsMatchErr)
		chain.lastEDECode = edns.EDECodeDNSSECBogus
		return false, nil
	}
	log.Debugf("SECURITY: zone cut — verified DNSKEY for %s (key_tag=%d)", childZone, matchedKey.KeyTag())

	// Cache the verified child zone DNSKEYs
	crypto.CacheZoneKeys(childZone, dnskeyRecords)

	// Validate the original answer against the child zone's DNSKEYs.
	// Return (false, nil) on DNSSEC validation failure so the caller applies
	// the SERVFAIL check. The EDE code is set in chain.lastEDECode.
	validated, valErr := crypto.ValidateResponse(response, childZone, dnskeyRecords)
	if valErr != nil {
		log.Debugf("SECURITY: zone cut — answer RRSIG verification failed for %s: %v", question.Name, valErr)
		chain.lastEDECode = edns.EDECodeDNSSECBogus
		return false, nil
	}
	if !validated {
		chain.lastEDECode = edns.EDECodeRRSIGsMissing
		return false, nil
	}
	return true, nil
}
func (rr *Recursive) isZoneCut(response *dns.Msg, currentDomain string) bool {
	return rr.getZoneCutSigner(response, currentDomain) != ""
}
