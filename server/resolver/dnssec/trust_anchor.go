package dnssec

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// IANA root-anchors.xml types (https://data.iana.org/root-anchors/root-anchors.xml).

type ianaTrustAnchor struct {
	XMLName    xml.Name        `xml:"TrustAnchor"`
	KeyDigests []ianaKeyDigest `xml:"KeyDigest"`
}

type ianaKeyDigest struct {
	ValidFrom  string `xml:"validFrom,attr"`
	ValidUntil string `xml:"validUntil,attr"`
	KeyTag     uint32 `xml:"KeyTag"`
	Algorithm  uint8  `xml:"Algorithm"`
	DigestType uint8  `xml:"DigestType"`
	Digest     string `xml:"Digest"`
	PublicKey  string `xml:"PublicKey"`
	Flags      uint32 `xml:"Flags"`
}

const (
	trustAnchorFileName = "root-anchors.xml"
	trustAnchorURL      = "https://data.iana.org/root-anchors/root-anchors.xml"

	// dnsFlagRevoke is the DNSKEY REVOKE flag (RFC 5011 §2.1).
	dnsFlagRevoke = 0x0080
)

var errNoValidAnchor = errors.New("no valid trust anchors found")

// loadTrustAnchorsFromFile parses an IANA root-anchors.xml file and returns the
// DNSKEY records for all valid KSK entries (those with PublicKey + Flags and
// not yet expired, and not revoked per RFC 5011 §2.1).
func loadTrustAnchorsFromFile(path string) ([]*dns.DNSKEY, error) {
	//nolint:gosec // path is derived from os.Executable(), not user input
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ta ianaTrustAnchor
	if err := xml.Unmarshal(data, &ta); err != nil {
		return nil, fmt.Errorf("xml parse error: %w", err)
	}

	now := time.Now().UTC()
	var keys []*dns.DNSKEY

	for i := range ta.KeyDigests {
		kd := &ta.KeyDigests[i]

		// Only use entries that contain a public key (KSK records).
		if kd.PublicKey == "" || kd.Flags == 0 {
			continue
		}

		// Skip keys that are not yet valid: RFC 7958 anchors may be published
		// ahead of their validFrom and must not be trusted early.
		if kd.ValidFrom != "" {
			validFrom, err := time.Parse(time.RFC3339, kd.ValidFrom)
			if err != nil {
				log.Debugf("SECURITY: unparseable validFrom for trust anchor key_tag=%d: %v — skipping", kd.KeyTag, err)
				continue
			}
			if now.Before(validFrom) {
				log.Debugf("SECURITY: skipping trust anchor that is not yet valid (key_tag=%d, valid_from=%s)", kd.KeyTag, kd.ValidFrom)
				continue
			}
		}

		// Skip expired keys. Fail closed on malformed timestamps: a
		// security-critical trust store must not accept unparseable data.
		if kd.ValidUntil != "" {
			validUntil, err := time.Parse(time.RFC3339, kd.ValidUntil)
			if err != nil {
				log.Debugf("SECURITY: unparseable validUntil for trust anchor key_tag=%d: %v — skipping", kd.KeyTag, err)
				continue
			}
			if now.After(validUntil) {
				log.Debugf("SECURITY: skipping expired trust anchor (key_tag=%d, valid_until=%s)", kd.KeyTag, kd.ValidUntil)
				continue
			}
		}

		// Construct a DNSKEY record string and parse it.
		rr, err := dns.New(fmt.Sprintf(". IN DNSKEY %d 3 %d %s", kd.Flags, kd.Algorithm, kd.PublicKey))
		if err != nil {
			log.Debugf("SECURITY: failed to parse trust anchor key_tag=%d from file: %v", kd.KeyTag, err)
			continue
		}
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			log.Debugf("SECURITY: trust anchor key_tag=%d from file is not a DNSKEY record", kd.KeyTag)
			continue
		}
		if dnskey.Flags&dns.FlagSEP == 0 || dnskey.Flags&dns.FlagZONE == 0 {
			log.Debugf("SECURITY: trust anchor key_tag=%d from file missing required DNSKEY flags (SEP/ZONE)", kd.KeyTag)
			continue
		}
		if dnskey.Flags&dnsFlagRevoke != 0 {
			log.Debugf("SECURITY: skipping revoked trust anchor key_tag=%d (RFC 5011 §2.1)", kd.KeyTag)
			continue
		}
		// RFC 7958 §2.1: the XML KeyTag must match the reconstructed key, or
		// the file is corrupt or tampered — fail closed rather than trust it.
		if kd.KeyTag != 0 && uint32(dnskey.KeyTag()) != kd.KeyTag {
			log.Debugf("SECURITY: trust anchor key tag mismatch (computed=%d, xml=%d) — skipping", dnskey.KeyTag(), kd.KeyTag)
			continue
		}
		// The XML digest must match the reconstructed key (RFC 7958 §2.1):
		// the digest is the integrity check the file format intends.
		if kd.Digest != "" {
			want, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(kd.Digest))
			if err != nil {
				log.Debugf("SECURITY: unparseable digest for trust anchor key_tag=%d: %v — skipping", kd.KeyTag, err)
				continue
			}
			ds := dnskey.ToDS(kd.DigestType)
			if ds == nil {
				// Fork's ToDS returns nil for unsupported digest types (e.g. GOST)
				// and un-packable keys — fail closed like every other malformed
				// anchor branch instead of dereferencing nil.
				log.Debugf("SECURITY: unsupported digest type %d for trust anchor key_tag=%d — skipping", kd.DigestType, kd.KeyTag)
				continue
			}
			got, err := hex.DecodeString(ds.Digest)
			if err != nil || !bytes.Equal(got, want) {
				log.Debugf("SECURITY: trust anchor digest mismatch (key_tag=%d) — skipping", kd.KeyTag)
				continue
			}
		}
		keys = append(keys, dnskey)
		log.Debugf("SECURITY: loaded trust anchor from file (key_tag=%d, algorithm=%s)", dnskey.KeyTag(), dns.AlgorithmToString[dnskey.Algorithm])
	}

	if len(keys) == 0 {
		return nil, errNoValidAnchor
	}
	return keys, nil
}
