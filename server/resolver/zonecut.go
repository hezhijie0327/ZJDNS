package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/resolver/dnssec"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// stripCrossZoneRecords removes answer records whose RRSIG signer name is
// from a different zone hierarchy than the given zone. These records need
// independent DNSSEC validation via CNAME chain following.
func stripCrossZoneRecords(answer, extra []dns.RR, zone string) []dns.RR {
	normalized := zdnsutil.NormalizeDomain(zone)
	if normalized == "" {
		return answer
	}
	allSigs := dnssec.CollectRRSIGs(answer, extra)

	result := make([]dns.RR, 0, len(answer))
	for _, r := range answer {
		if r == nil {
			continue
		}
		h := r.Header()
		sigs := dnssec.FindRRSIGs(allSigs, h.Name, dns.RRToType(r))
		if len(sigs) == 0 {
			result = append(result, r)
			continue
		}
		inZone := false
		for _, sig := range sigs {
			signer := zdnsutil.NormalizeDomain(sig.SignerName)
			if signer == normalized || strings.HasSuffix(signer, "."+normalized) {
				inZone = true
				break
			}
		}
		if inZone {
			result = append(result, r)
		} else {
			log.Debugf("SECURITY: stripping cross-zone record %s/%s from %s answer", h.Name, dns.TypeToString[dns.RRToType(r)], zone)
		}
	}
	return result
}

func (r *Recursive) getZoneCutSigner(response *dns.Msg, currentDomain string) string {
	if response == nil || len(response.Answer) == 0 {
		return ""
	}

	normalizedCurrent := zdnsutil.NormalizeDomain(currentDomain)
	if normalizedCurrent == "" {
		return ""
	}

	rrsigs := dnssec.CollectRRSIGs(response.Answer, response.Extra)
	for _, rrsig := range rrsigs {
		if rrsig == nil {
			continue
		}
		signerName := zdnsutil.NormalizeDomain(rrsig.SignerName)
		if signerName != normalizedCurrent &&
			strings.HasSuffix(signerName, "."+normalizedCurrent) {
			return signerName
		}
	}

	return ""
}

func (r *Recursive) resolveZoneCut(ctx context.Context, response *dns.Msg, nameservers []string, question Question, currentDomain string, ecs *edns.ECSOption, forceTCP bool, chain *dnssecChain) (bool, error) {
	crypto := r.resolver.validator.Crypto

	childZone := r.getZoneCutSigner(response, currentDomain)
	if childZone == "" {
		return false, errors.New("could not determine child zone name from RRSIG signer")
	}

	if len(chain.zoneDNSKEYs) == 0 {
		r.ensureZoneDNSKEYs(ctx, nameservers, currentDomain, chain)
	}
	parentKeys := chain.zoneDNSKEYs
	if len(parentKeys) == 0 {
		parentKeys = chain.parentDNSKEYs
	}
	if len(parentKeys) == 0 {
		return false, fmt.Errorf("no parent DNSKEYs available to verify DS for %s", childZone)
	}

	dsQuestion := Question{Name: dnsutil.Fqdn(childZone), Qtype: dns.TypeDS, Qclass: dns.ClassINET}
	dsResp, _, dsErr := r.queryNameserversConcurrent(ctx, nameservers, dsQuestion, ecs, forceTCP, currentDomain, r.resolver.validator.Hijack)
	if dsErr != nil {
		return false, fmt.Errorf("DS query for %s failed: %w", childZone, dsErr)
	}
	defer pool.DefaultMessage.Put(dsResp)

	dsRecords := dnssec.FindDS(dsResp.Answer)
	dsRecords = append(dsRecords, dnssec.FindDS(dsResp.Ns)...)
	if len(dsRecords) == 0 {
		chain.childDS = nil
		chain.dsPresentButUnverified = false
		return false, nil
	}

	allSigs := dnssec.CollectRRSIGs(dsResp.Answer, dsResp.Ns, dsResp.Extra)
	dsRRSIGs := dnssec.FindRRSIGs(allSigs, dnsutil.Fqdn(childZone), dns.TypeDS)
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

	chain.childDS = verifiedDS

	dnskeyQuestion := Question{Name: dnsutil.Fqdn(childZone), Qtype: dns.TypeDNSKEY, Qclass: dns.ClassINET}
	dnskeyResp, _, dnskeyErr := r.queryNameserversConcurrent(ctx, nameservers, dnskeyQuestion, ecs, forceTCP, currentDomain, r.resolver.validator.Hijack)
	if dnskeyErr != nil {
		return false, fmt.Errorf("DNSKEY query for %s failed: %w", childZone, dnskeyErr)
	}
	defer pool.DefaultMessage.Put(dnskeyResp)

	dnskeyRecords := dnssec.FindDNSKEYs(dnskeyResp.Answer)
	if len(dnskeyRecords) == 0 {
		return false, fmt.Errorf("no DNSKEY records found for %s", childZone)
	}

	matchedKey, dsMatchErr := crypto.VerifyDelegationDS(verifiedDS, dnskeyRecords)
	if dsMatchErr != nil {
		log.Debugf("SECURITY: zone cut — DS→DNSKEY mismatch for %s: %v", childZone, dsMatchErr)
		chain.lastEDECode = edns.EDECodeDNSSECBogus
		return false, nil
	}
	log.Debugf("SECURITY: zone cut — verified DNSKEY for %s (key_tag=%d)", childZone, matchedKey.KeyTag())

	crypto.CacheZoneKeys(childZone, dnskeyRecords)

	validated, valErr := crypto.IsResponseValid(response, childZone, dnskeyRecords)
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

func (r *Recursive) isZoneCut(response *dns.Msg, currentDomain string) bool {
	return r.getZoneCutSigner(response, currentDomain) != ""
}
