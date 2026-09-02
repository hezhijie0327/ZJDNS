# Foundation 审计 (internal/*) — 17 findings: 1H/6M/10L

| ID | 严重度 | 位置 | 问题 | 状态 |
|----|--------|------|------|------|
| F1 | HIGH | spillfile.go:506,616 vs 846-863 | Get/Indexed 锁外 ReadAt 与 Compact close/reassign 竞态(use-after-close + 世代错位) | ✅ |
| F2 | MED | spillfile.go:122,435 | maxKeyLen=1<<16 但字段 uint16 → 65536B key 写 0 长度记录,重启截断尾部 | ✅ |
| F3 | MED | demux/udp.go:44-239 | NewUDPDemux 死代码;peers map 无界;readLoop 错误热循环;push 忽略 | ✅ 删除 |
| F4 | MED | demux/detect.go:72-111 | DetectTCPProtocol 文档说 0x00-0x04→dnscrypt 其他 unknown,代码 default 全送 dnscrypt | ✅ |
| F5 | MED | dnsutil/case.go:36-95 | FoldCase 无条件 rr.String()+Builder(0x20 未启用时纯浪费,每 RR 2+ 分配) | ✅ |
| F6 | MED | demux/tcp.go:93, udp.go:176 | acceptLoop/readLoop 无 defer HandlePanic | ✅ |
| F7 | MED | stamp/parse.go:60-77,108-125,251-267 | 端口规范化块复制 3 份且已漂移 | ✅ |
| F8 | LOW | demux/queue.go:47-70 | Close 不排水不关连接;push 取消后可假成功 | ✅ |
| F9 | LOW | log/log.go:354-355,208 | SetLevelFilter 孤儿注释;29 vs 28 前缀计数 | ✅ |
| F10 | LOW | spillfile.go:86-100,655,245 | Warm 文档错挂 Store;Create 文档过期 | ✅ |
| F11 | LOW | dnsutil/download.go:15, ipdetect/ipdetect.go:32 | 注释乱码 "config.the local" | ✅ |
| F12 | LOW | lrumap/lru.go:1, dnscryptcrypto/pq.go:13-29, stamp.go:1 | 包名/类型文档错挂 | ✅ |
| F13 | LOW | topk/topk.go:90-104 | TopN 负数 panic(未指定 n) | ✅ |
| F14 | LOW | demux/queue.go:25,57,179 等 | 魔法数字;`_ =` 无注释 | ✅ |
| F15 | LOW | spillfile.go:548-584 | 块解析器不查 wireLen 上限(32 位溢出路径) | ✅ |
| F16 | LOW | dnscryptcrypto/keys.go:47-54 | X25519KeyPairFromSeed 恒 nil error | ✅ |
| F17 | LOW | latency/probes.go:349-354 | probeHTTP 不排空 body → HTTP/2/3 连接不复用 | ✅ |
