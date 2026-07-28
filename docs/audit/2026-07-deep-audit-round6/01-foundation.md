# Foundation Audit — internal/* 包

**日期**: 2026-07-28
**范围**: internal/dns64, dnscryptcrypto, dnsutil, ipdetect, ipttl, latency, log, lrumap, pending, pool, siphash, stamp, ttl (38 文件)

---

## 发现汇总

| # | 严重程度 | 分类 | 文件:行 | 描述 |
|---|----------|------|---------|------|
| F1 | MEDIUM | validation | `internal/dnscryptcrypto/dns.go:58-62` | `ReadPrefixed` 接受零长度前缀，绕过 `MaxMsgSize` 检查 |
| F2 | LOW | panic | `internal/siphash/siphash.go:10-14` | `Sum64` 无 nil key 检查，裸指针解引用 |
| F3 | LOW | data-corruption | `internal/dnsutil/https_dns.go:21-74` | DoH GET 后 `msg.Data` 保留 ID=0 的过期线格式 |
| F4 | LOW | comment-accuracy | `internal/latency/probes.go:125` | 重复的内联注释 |
| F5 | LOW | rfc-compliance | `internal/latency/probes.go:261` | 冗余的空 User-Agent header 设置 |
| F6 | LOW | panic | `internal/dnscryptcrypto/xsecretbox.go:57-61,101-105` | key/nonce 大小不正确时 panic（已文档化） |
| F7 | LOW | comment-accuracy | `internal/dnscryptcrypto/encryption.go:52-54` | "rejection sampling" 注释不准确（实际是 mask-and-modulo） |
| F8 | LOW | memory | `internal/log/log.go:324-333` | `TimeCache` 不调用 `Stop()` 时 goroutine 泄漏 |
| F9 | LOW | panic | `internal/log/log.go:246` | 零值 `Logger` 的 `m.writer` nil 访问 |
| F10 | LOW | validation | `internal/latency/prober.go:147-154` | `normalizeProbeProtocol` 大小写敏感性漏洞 |
| F11 | LOW | performance | `internal/dnsutil/dnsutil.go:72` | `HandlePanic` 每次调用分配 8KB（已文档化权衡） |
| F12 | LOW | architecture | `internal/pool/pool.go:64-68` | 共享 buffer pool 跨 UDP/TCP（已文档化权衡） |
| F13 | LOW | panic | `internal/ipttl/ipttl.go:48-63` | pc4+pc6 均为 nil 时静默丢弃数据报 |
| F14 | LOW | comment-accuracy | `internal/dnscryptcrypto/encrypted.go:102-105` | `Encrypt` godoc 关于 Nonce 的误导性描述 |

---

## 关键发现

### F1 — ReadPrefixed 接受零长度前缀 (MEDIUM)

`ReadPrefixed` 验证 `packetLen > dns.MaxMsgSize` 但未拒绝 `packetLen == 0`。`\x00\x00` 长度前缀绕过守卫，产生零长度缓冲区，DNS 解析时产生混淆的错误信息。

**修复**: 在分配前添加 `if packetLen == 0 { return nil, ErrEmptyMessage }`。

---

## 无问题维度

- 锁正确性：所有内部包均无双锁死锁或锁顺序违规
- 死代码：未发现死代码
- 耦合：无导入分层违规
- 函数排序：所有文件遵循 `type → const → var → func`
