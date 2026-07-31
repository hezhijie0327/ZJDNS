# RFC 8914 (EDE) 审计报告

## 发现清单

| # | 严重度 | 位置 | 描述 |
|---|--------|------|------|
| A | HIGH | `recursive.go:29` | `lastDNSSECEDECode` 跨查询共享 → EDE 串扰 |
| B | MED | `forward.go:266,287` | 查询内上游 EDE 归属错误 |
| C | MED | `forward.go:33` | EDE 指针逃逸 pool 生命周期 |
| D | LOW | `bridge.go:158-166` | 截断保留 EDE 丢弃答案（颠倒 RFC §3） |
| E | HIGH | `zone.go:63` | 失败 rcode 用 EDE 4 而非 15/16/17 (§4.5) |
| F | LOW | `validation.go:32,81` | 畸形查询用 EDE 24 而非 0/21 (§4.25) |
| G | LOW | `dnssec_chain.go:380,419` | 网络失败用 EDE 9 而非 22/23 (§4.10) |
| H | MED | `crypto.go:97-101` `dnssec_chain.go:454` | 过期/未生效签名塌缩为 EDE 6，未区分 7/8 |
| I | LOW | `cache_store.go:129-131,180` | 转发 EDE 无源归属，SERVFAIL 丢弃 ExtraText |
| J | LOW | `response.go:64-69` | EDE 附加到无 OPT 查询的响应 |
