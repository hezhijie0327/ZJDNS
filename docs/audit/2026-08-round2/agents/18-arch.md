# arch 审计

> agent: `a721b755d93862480`

发现数: 4

## arch-01 — CRITICAL

- **位置**: `cache/store.go:267`
- **类别**: validation
- **摘要**: Get 无条件按 0x02 pre-packed 格式解析 BLOB，旧格式（zstd 无格式字节）条目在升级后缓存命中即 panic
- **描述**: Get（cache/store.go:267-273）从不检查 msgWire[0] == cacheFormatPrePacked，直接读 `numOffsets := int(binary.BigEndian.Uint16(msgWire[1:3]))`。v3.11.12 之前的构建（含上一轮审计基线 93611d5 及全部 v3.11.x ≤11）写入的 entries 行是纯 zstd 压缩 wire（无格式字节，旧 Set 直接 `msgWire := zdnsutil.Compress(msg.Data)`，见 93611d5:cache/store.go:340）。旧 BLOB 前 4 字节是 zstd magic 0x28 0xB5 0x2F 0xFD → msgWire[1:3] = 0xB5 0x2F = 46383 → line 270-271 循环 `msgWire[3+i*2:]` 在 i≈len/2 处 slice bounds panic（DNS wire 压缩后远小于 92769 字节，必 panic）；即便 BLOB 足够长，偏移表也是垃圾值，buildFromPrePacked 会在随机字节偏移写 TTL 破坏响应。database/migration.go 无清空 entries 的迁移，升级后旧条目存活最长 7 天（RFC 8767 TTL 上限），期间每次命中该条目的查询都 panic（被 HandlePanic 恢复后查询静默丢弃 → 客户端超时）。
- **风险**: 带既有 cache.db 升级到 v3.11.12+：旧缓存条目命中即 panic，查询静默丢失；大条目场景下垃圾 TTL 偏移直接损坏出站响应。升级路径（上一轮 H8 同属升级安全）出现新的 CRITICAL 回归。
- **修复**: Get 读取前校验格式：`if len(msgWire) < 3 || msgWire[0] != cacheFormatPrePacked { return nil, false, false }`（按 miss 处理，重新解析后以新格式回写）。格式标记常量已存在（store.go:50），只缺读侧校验。建议补充旧格式 BLOB 的单元测试。

## arch-02 — MEDIUM

- **位置**: `edns/edns.go:35`
- **类别**: docs
- **摘要**: RFC 6975 var 块插在 NewHandler 的 godoc 注释与函数之间，NewHandler 丢失文档注释、var 块继承错误注释
- **描述**: edns/edns.go:35-49：`// NewHandler creates a Handler...` 注释行之后插入 `var (dauAlgorithms/dhuAlgorithms/n3uAlgorithms)` 块，`func NewHandler`（line 51）前无任何注释。Go doc 规则下注释归属于紧随其后的声明——现在 `NewHandler`（导出公开 API）无 godoc，而 var 块继承了一条以 "NewHandler creates..." 开头的误导性注释，且 "RFC 6975 algorithm lists..." 说明被拼进了 NewHandler 的文档行。delta 中其余新增导出符号（cache.AcquireTTLOffsets/ReleaseTTLOffsets/WireHasDNSSEC、resolver.WithMQType/MQTypeFromContext、middleware.MQTYPE/Any、config.InfoURL 及 4 个常量）均有完整 godoc，此处是唯一破坏。
- **风险**: 公开 API 文档缺失（方法论 6.2 #11 反模式），godoc 渲染出错误归属的注释，误导维护者；若启用 exported-doc linter 则 CI 直接报错。
- **修复**: 把 var 块移到 `func NewHandler` 之后（或 `type Handler` 之前），恢复 `// NewHandler creates...` 与 `func NewHandler` 的相邻性；var 块自带 dauAlgorithms/dhuAlgorithms/n3uAlgorithms 注释即可。

## arch-03 — MEDIUM

- **位置**: `server/bridge.go:337`
- **类别**: coupling
- **摘要**: packed wire 名称跳过逻辑在 3 处独立重复实现（bridge.go/cache×2），且 cache 数据存储包导出 wire 解析工具供 handler 层消费
- **描述**: 同一段"跳过 packed 消息中的域名（label/压缩指针）"逻辑存在三份：server/bridge.go:337 `skipWireName`（与 cache 版逐字节相同）、cache/store.go:174 `dnsSkipName`、cache/cache.go:121 `rebuildResponseWire` 内联手写循环。同时 cache（数据存储 domain 包）导出 wire 格式解析工具 `WireHasDNSSEC`（store.go:145）、`AcquireTTLOffsets`/`ReleaseTTLOffsets`，唯一消费者是 handler/middleware（response.go 的直发快路径）与 handler/response.go——属于驻留错层：wire 格式工具应放 internal/dnsutil（cache 与 server 均已导入、无循环风险）。三份实现各自演进（如 pointer 处理细节），修复一处不修另一处即产生行为漂移。
- **风险**: wire 解析逻辑三处漂移：新 bug 需修三遍，压缩指针/RDATA 边界处理不一致会在边界场景（畸形响应、截断 wire）产生分歧行为；domain 包承担 handler 层职责破坏 cohesion。
- **修复**: 将 dnsSkipName/skipWireName/WireHasDNSSEC/scanTTLOffsets/truncateWire 统一收敛到 internal/dnsutil（导出 SkipNameInWire 等），cache、server/bridge.go、handler 引用同一实现；cache 保留对 dnsutil 的调用。注意保留响应路径的零分配属性（函数签名不变即可）。

## arch-04 — LOW

- **位置**: `cache/store.go:121`
- **类别**: comment
- **摘要**: scanTTLOffsets 注释引用不存在的 releaseTTLOffsets，实际函数名为 ReleaseTTLOffsets
- **描述**: cache/store.go:121 注释 "The returned slice is pool-owned — release with releaseTTLOffsets when done." 引用了小写 `releaseTTLOffsets`，该符号不存在——实际导出函数是 `ReleaseTTLOffsets`（store.go:103）。注释与代码不符，误导调用方（若按注释搜索会找不到符号）。
- **风险**: 维护者按注释搜索 releaseTTLOffsets 找不到符号，怀疑代码不一致；池归还纪律（方法论 4.2 池归还模式）的注释锚点失效。
- **修复**: 将注释中的 releaseTTLOffsets 改为 ReleaseTTLOffsets。

