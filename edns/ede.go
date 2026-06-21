package edns

import (
	"fmt"

	"github.com/miekg/dns"
)

// EDE info codes as defined in RFC 8914.
const (
	EDECodeOtherError                 uint16 = 0
	EDECodeUnsupportedDNSKEYAlgorithm uint16 = 1
	EDECodeUnsupportedDSDigestType    uint16 = 2
	EDECodeStaleAnswer                uint16 = 3
	EDECodeForgedAnswer               uint16 = 4
	EDECodeDNSSECIndeterminate        uint16 = 5
	EDECodeDNSSECBogus                uint16 = 6
	EDECodeSignatureExpired           uint16 = 7
	EDECodeSignatureNotYetValid       uint16 = 8
	EDECodeDNSKEYMissing              uint16 = 9
	EDECodeRRSIGsMissing              uint16 = 10
	EDECodeNoZoneKeyBitSet            uint16 = 11
	EDECodeNSECMissing                uint16 = 12
	EDECodeCachedError                uint16 = 13
	EDECodeNotReady                   uint16 = 14
	EDECodeBlocked                    uint16 = 15
	EDECodeCensored                   uint16 = 16
	EDECodeFiltered                   uint16 = 17
	EDECodeProhibited                 uint16 = 18
	EDECodeStaleNXDomainAnswer        uint16 = 19
	EDECodeNotAuthoritative           uint16 = 20
	EDECodeNotSupported               uint16 = 21
	EDECodeNoReachableAuthority       uint16 = 22
	EDECodeNetworkError               uint16 = 23
	EDECodeInvalidData                uint16 = 24
)

// EDEOption represents an Extended DNS Error option with an info code and
// optional text.
type EDEOption struct {
	InfoCode  uint16
	ExtraText string
}

// NewEDEOption creates an EDE option with the given info code and extra text.
func NewEDEOption(infoCode uint16, extraText string) *EDEOption {
	return &EDEOption{InfoCode: infoCode, ExtraText: extraText}
}

// EDECodeString returns a human-readable description for the given EDE info
// code.
func EDECodeString(code uint16) string {
	switch code {
	case EDECodeOtherError:
		return "Other Error"
	case EDECodeUnsupportedDNSKEYAlgorithm:
		return "Unsupported DNSKEY Algorithm"
	case EDECodeUnsupportedDSDigestType:
		return "Unsupported DS Digest Type"
	case EDECodeStaleAnswer:
		return "Stale Answer"
	case EDECodeForgedAnswer:
		return "Forged Answer"
	case EDECodeDNSSECIndeterminate:
		return "DNSSEC Indeterminate"
	case EDECodeDNSSECBogus:
		return "DNSSEC Bogus"
	case EDECodeSignatureExpired:
		return "Signature Expired"
	case EDECodeSignatureNotYetValid:
		return "Signature Not Yet Valid"
	case EDECodeDNSKEYMissing:
		return "DNSKEY Missing"
	case EDECodeRRSIGsMissing:
		return "RRSIGs Missing"
	case EDECodeNoZoneKeyBitSet:
		return "No Zone Key Bit Set"
	case EDECodeNSECMissing:
		return "NSEC Missing"
	case EDECodeCachedError:
		return "Cached Error"
	case EDECodeNotReady:
		return "Not Ready"
	case EDECodeBlocked:
		return "Blocked"
	case EDECodeCensored:
		return "Censored"
	case EDECodeFiltered:
		return "Filtered"
	case EDECodeProhibited:
		return "Prohibited"
	case EDECodeStaleNXDomainAnswer:
		return "Stale NXDOMAIN Answer"
	case EDECodeNotAuthoritative:
		return "Not Authoritative"
	case EDECodeNotSupported:
		return "Not Supported"
	case EDECodeNoReachableAuthority:
		return "No Reachable Authority"
	case EDECodeNetworkError:
		return "Network Error"
	case EDECodeInvalidData:
		return "Invalid Data"
	default:
		return fmt.Sprintf("Unknown Error (%d)", code)
	}
}

// ParseEDE extracts the Extended DNS Error option from a DNS message.
func (m *Handler) ParseEDE(msg *dns.Msg) *EDEOption {
	if m == nil || msg == nil || msg.Extra == nil {
		return nil
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, option := range opt.Option {
		if ede, ok := option.(*dns.EDNS0_EDE); ok {
			return &EDEOption{
				InfoCode:  ede.InfoCode,
				ExtraText: ede.ExtraText,
			}
		}
	}
	return nil
}
