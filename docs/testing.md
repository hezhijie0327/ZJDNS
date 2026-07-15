# Testing & Debug Config

## Debug Config

`config.debug.json` (not committed):

```json
{
  "server": {
    "log_level": "debug",
    "protocol": {
      "udp": "15353",
      "tcp": "15353"
    },
    "features": {
      "hijack_protection": true,
      "dnssec_enforce": true,
      "cache": {
        "max_entries": 10000,
        "db_path": "cache.db"
      },
      "latency_probe": [
        { "protocol": "ping", "timeout": 200 },
        { "protocol": "tcp", "port": 443, "timeout": 200 }
      ]
    }
  },
  "upstream": [
    { "address": "builtin_recursive" }
  ]
}
```

Port 15353 (non-privileged), pure recursive, cache enabled with latency probing. Start: `./zjdns -config config.debug.json`.

## Test Domains

Verify hijack detection: `grep -E "hijack probe|hijack detected|tcp=true" /tmp/zjdns.log`.

```bash
# Hijack detection (should trigger TCP fallback)
dig @127.0.0.1 -p 15353 www.google.com www.youtube.com chatgpt.com A +short

# Normal resolution (no fallback)
dig @127.0.0.1 -p 15353 www.baidu.com dns.weixin.qq.com.cn updates.cdn-apple.com A +short

# DNSSEC (requires dnssec_enforce: true)
dig @127.0.0.1 -p 15353 sigfail.ippacket.stream A +short   # bogus → SERVFAIL
dig @127.0.0.1 -p 15353 sigok.ippacket.stream A +short     # valid → NOERROR

# EDNS FORMERR retry
dig @127.0.0.1 -p 15353 zhijie-online.mail.protection.outlook.com A +short

# QNAME minimisation CNAME corner case (RFC 9156 §2.3)
dig @127.0.0.1 -p 15353 home.console.aliyun.com A

# Stats + DB ops
dig @127.0.0.1 -p 15353 zjdns.stats CH TXT +short
dig @127.0.0.1 -p 15353 zjdns.db.clear.stats CH TXT +short
./zjdns --sql cache.db "SELECT result, rcode, COUNT(*) FROM request_log GROUP BY result, rcode"
```

## TLCP (国密) Test

```bash
# External upstream (DNSPod, requires skip_tls_verify)
./zjdns -config <(echo '{"server":{"protocol":{"udp":"53535"}},"upstream":[{"address":"https://sm2.doh.pub/dns-query","protocol":"doh-tlcp","server_name":"sm2.doh.pub","skip_tls_verify":true}]}') &

# Self-hosted TLCP server (self-signed SM2 certs)
./zjdns -config <(echo '{"server":{"protocol":{"tlcp":"8530","http_tlcp":{"port":"4430","endpoint":"/dns-query"}},"certificate":{"domain":"tlcp.local","tlcp":{"self_signed":true}},"features":{"hijack_protection":false,"cache":{"max_entries":0}}},"upstream":[{"address":"builtin_recursive"}]}') &

# TLCP DoH loopback
./zjdns -config <(echo '{"server":{"protocol":{"udp":"55454"}},"upstream":[{"address":"https://127.0.0.1:4430/dns-query","protocol":"doh-tlcp","server_name":"ZJDNS TLCP","skip_tls_verify":true}]}') &
dig @127.0.0.1 -p 55454 www.baidu.com A +short

# DTLCP loopback (use [::1] on Windows)
./zjdns -config <(echo '{"server":{"protocol":{"dtlcp":"8542"},"certificate":{"domain":"dtlcp.local","tlcp":{"self_signed":true}},"features":{"hijack_protection":false,"cache":{"max_entries":0}}},"upstream":[{"address":"builtin_recursive"}]}') &
./zjdns -config <(echo '{"server":{"protocol":{"udp":"55454"}},"upstream":[{"address":"127.0.0.1:8542","protocol":"dtlcp","server_name":"dtlcp.local","skip_tls_verify":true}]}') &
dig @127.0.0.1 -p 55454 www.baidu.com A +short
```
