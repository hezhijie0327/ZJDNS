# socks5srv — minimal SOCKS5 UDP-ASSOCIATE test proxy

Loopback SOCKS5 server for `docs/debug/defense/spoofguard-socks5.json`
(RFC 1928 §7 UDP ASSOCIATE). Replaces the `go run
github.com/things-go/go-socks5/cmd/socks5@latest` helper from earlier
revisions of DEBUG.md — that command no longer works (the upstream module
dropped its cmd package) and the library's proxy does not echo UDP relays.

```bash
go build -o /tmp/socks5srv ./docs/debug/socks5srv
/tmp/socks5srv &          # listens on 127.0.0.1:11080, no auth
```

Scope (deliberately minimal, test-only):
- TCP control: greeting (no-auth), CONNECT rejected (UDP ASSOCIATE only)
- One relay socket per control conn; first client datagram registers the
  peer; one persistent outbound socket forwards unwrapped datagrams and
  pumps replies back wrapped (ATYP=1)
- No frag reassembly, no auth methods beyond no-auth, no IPv6 relay out
