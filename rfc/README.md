# RFC Reference Files

These files are the complete text of the RFC standards and drafts that ZJDNS
implements or references.  They are used for compliance auditing and as
authoritative reference material.

## Source

All RFCs were downloaded from `https://www.rfc-editor.org/rfc/rfc{N}.txt`.
The DNSCrypt draft was downloaded from the IETF archive.

## File Index

| File | Title |
|------|-------|
| rfc1928.txt | SOCKS Protocol Version 5 |
| rfc1929.txt | Username/Password Authentication for SOCKS5 |
| rfc4033.txt | DNS Security Introduction and Requirements |
| rfc4034.txt | Resource Records for the DNS Security Extensions |
| rfc4035.txt | Protocol Modifications for the DNS Security Extensions |
| rfc5155.txt | DNS Security (DNSSEC) Hashed Authenticated Denial of Existence |
| rfc6052.txt | IPv6 Addressing of IPv4/IPv6 Translators |
| rfc6147.txt | DNS64: DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers |
| rfc6840.txt | Clarifications and Implementation Notes for DNS Security (DNSSEC) |
| rfc6891.txt | Extension Mechanisms for DNS (EDNS(0)) |
| rfc7766.txt | DNS Transport over TCP - Implementation Requirements |
| rfc7828.txt | The edns-tcp-keepalive EDNS0 Option |
| rfc7830.txt | The EDNS(0) Padding Option |
| rfc7858.txt | Specification for DNS over Transport Layer Security (TLS) |
| rfc7871.txt | Client Subnet in DNS Queries |
| rfc8310.txt | Usage Profiles for DNS over TLS and DNS over DTLS |
| rfc8467.txt | Padding Policies for Extension Mechanisms for DNS (EDNS(0)) |
| rfc8484.txt | DNS Queries over HTTPS (DoH) |
| rfc8767.txt | Serving Stale Data to Improve DNS Resiliency |
| rfc8914.txt | Extended DNS Errors |
| rfc9000.txt | QUIC: A UDP-Based Multiplexed and Secure Transport |
| rfc9018.txt | Interoperable DNS Server Cookies |
| rfc9114.txt | HTTP/3 |
| rfc9156.txt | DNS Query Name Minimisation to Improve Privacy |
| rfc9250.txt | DNS over Dedicated QUIC Connections |
| rfc9461.txt | Service Binding and Parameter Specification via the DNS (SVCB) |
| rfc9462.txt | Discovery of Designated Resolvers (DDR) |
| draft-denis-dprive-dnscrypt-10.txt | The DNSCrypt Protocol |
| draft-denis-dns-stamps-02.txt | DNS Stamps |

## Update

To refresh all files:
```bash
cd rfc
for f in rfc*.txt; do
  n=$(echo $f | grep -oE '[0-9]+')
  curl -sL -o "$f" "https://www.rfc-editor.org/rfc/rfc${n}.txt"
done
curl -sL -o draft-denis-dprive-dnscrypt-10.txt \
  "https://www.ietf.org/archive/id/draft-denis-dprive-dnscrypt-10.txt"
curl -sL -o draft-denis-dns-stamps-02.txt \
  "https://www.ietf.org/archive/id/draft-denis-dns-stamps-02.txt"
```
