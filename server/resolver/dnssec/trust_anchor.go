package dnssec

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
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
)

var errNoValidAnchor = errors.New("no valid trust anchors found")

// loadTrustAnchorsFromFile parses an IANA root-anchors.xml file and returns the
// DNSKEY records for all valid KSK entries (those with PublicKey + Flags and
// not yet expired).
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

		// Skip expired keys.
		if kd.ValidUntil != "" {
			validUntil, err := time.Parse(time.RFC3339, kd.ValidUntil)
			if err != nil {
				log.Debugf("SECURITY: unparseable validUntil for trust anchor key_tag=%d: %v — accepting as valid", kd.KeyTag, err)
			} else if now.After(validUntil) {
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
		keys = append(keys, dnskey)
		log.Debugf("SECURITY: loaded trust anchor from file (key_tag=%d, algorithm=%s)", dnskey.KeyTag(), dns.AlgorithmToString[dnskey.Algorithm])
	}

	if len(keys) == 0 {
		return nil, errNoValidAnchor
	}
	return keys, nil
}
