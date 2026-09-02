# 交叉维度审计 — X(锁/goroutine/资源) 5 + E(错误/ctx/校验) 9 + C(日志/常量/RFC) 10

| ID | 严重度 | 位置 | 问题 | 状态 |
|----|--------|------|------|------|
| X1 | HIGH | cache/store.go:693,701 | (=D1) Put 后读 Data,竞态 + flag 永假 | ✅ |
| X2 | HIGH | tlcp/dtlcp.go:161-165 | (=P1) 裸 send | ✅ |
| X3 | MED | demux/queue.go:47-50 | Close 遗弃 ≤64 已缓冲连接 | ✅ |
| X4 | MED | shared/udp.go:743-755 | Shutdown 后 DNSCrypt drain goroutine 永挂 + 必然吃满后台关闭超时 | ✅ 并入 P3 |
| X5 | LOW | tlcp/dtlcp.go:172 | (=P-L10) | ✅ |
| E1 | MED | handler/handler.go:64 | NewHandler 8 位置参数、ctx 在末尾 | ✅ |
| E2 | LOW | stamp/stamp.go:97 | ErrTruncatedAddress 死 sentinel | ✅ |
| E3 | LOW | config/defaults.go:418 | PrivacyProfileOpportunistic 死常量+断头注释 | ✅ |
| E4 | LOW | 5 处 errors.As 两步式 → errors.AsType | ✅ |
| E5 | LOW | 3 处 err == io.EOF 直比 → errors.Is | ✅ |
| E6 | LOW | 5 处 sort.* → slices.* | ✅ |
| E7 | LOW | spillfile.go:768-772 | 手写 keys 收集 → slices.Sorted(maps.Keys) | ✅ |
| E8 | LOW | cache/store.go:260-307 | spill Put/Flush 错误静默(与 R2 并) | ✅ |
| E9 | LOW | cache/store.go:494 | Unpack 错误静默无日志 | ✅ |
| C-M1 | MED | cache_store.go:106 | ECS mismatch 每查询 Warn 无采样 | ✅ |
| C-M2 | MED | middleware/zone.go:86 | 远程可触发 Warn 洪水(destructive CHAOS) | ✅ |
| C-M3 | MED | cache/store.go:436,462 | 损坏条目每读 Warn 不自愈(=D8) | ✅ |
| C-M4 | MED | middleware/edns.go:176 | BADCOOKIE 硬编码 false → 安全传输上不填充(RFC 8467 §4) | ✅ |
| C-L1 | LOW | shared/*.go 6 处 | 非规范 SHARED: 前缀 | ✅ |
| C-L2 | LOW | tlcp/certs.go:128, dnssec/crypto.go:143 | RFC 5280/8624 未镜像 | ✅ 存档 |
| C-L3 | LOW | dnscryptcrypto/proto.go:24 vs pool/pool.go:28 | 4096 双处定义 | ✅ |
| C-L4 | LOW | config/defaults.go:189 | TCP idle 120s vs RFC 7766 "秒级" — 注释偏差 | ✅ 注释 |
| C-L5 | LOW | recursive_ns.go:58, bridge.go:270,302 | Debugf 参数未门控 | ✅ |
| C-L6 | LOW | shared/udp.go:380, plain/udp.go:789 | 语义字面量未命名 | ✅ |
