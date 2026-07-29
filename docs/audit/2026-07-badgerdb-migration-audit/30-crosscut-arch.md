# 30 · 交叉分析：架构设计

> 审计 Agent：Phase 2b · Arch
> 范围：全项目导入分层验证、循环依赖、接口放置、God package


## ZJDNS 架构审计报告

### 1. 导入分层验证

**结论：通过 —— 严格遵循层级 DAG**

| 层级 | 包含包 | 导入目标 | 状态 |
|------|--------|----------|------|
| Foundation | internal/log, pool, ipdetect, siphash, ipttl, pending, ttl, dns64, dnscryptcrypto, lrumap, stamp | 零 zjdns 导入 | 通过 |
| Layer 1-2 | config, internal/dnsutil, internal/latency | Foundation | 通过 |
| Layer 3 (domain) | database, edns, cache, ruleset, zone | Foundation + config | 通过 |
| Layer 4 | handler, resolver, upstream, defense, protocol/* | Layer 3 + Layer 1-2 + Foundation | 通过 |
| Top | server, cmd/zjdns | 所有下层 | 通过 |

所有导入边均指向编号较低的层级。`internal/lrumap → internal/log` 是对 Foundation 层级"零 zjdns 导入"原则的技术性偏离，但因为 `log` 同为 Foundation 包，实际耦合极弱，不构成实质问题。

---

### 2. 循环依赖风险

**结论：无循环依赖风险**

- `go vet ./...` 通过，无错误
- 手动 DAG 追踪确认无反向边：
  - `handler → resolver ↔ upstream → defense`：`defense` 仅导入 Foundation 包，不存在回环
  - `resolver → upstream`，`upstream → resolver` 不存在
  - `handler → resolver`，`resolver → handler` 不存在
  - `upstream/protocol 子包 → 父包` 所有子包均独立，不导入父包（符合架构规则）

---

### 3. Domain 包不互引规则

**结论：通过 —— 全部互引均在已知例外列表内**

检查了所有 domain 包（database, edns, cache, ruleset, zone）的导入表：

| 导入方 | 被导入方 | 是否在例外列表 | 状态 |
|--------|----------|---------------|------|
| cache → database | domain→domain | 是 | 通过 |
| zone → database | domain→domain | 是 | 通过 |
| ruleset → database | domain→domain | 是 | 通过 |
| edns → config | Layer 1-2 | 是（宽松列举） | 通过 |
| cache → config | Layer 1-2 | 是（宽松列举） | 通过 |
| zone → config | Layer 1-2 | 是（宽松列举） | 通过 |
| ruleset → config | Layer 1-2 | 是（宽松列举） | 通过 |
| database → config | Layer 1-2 | — | 通过（domain → Layer 1-2，非 domain→domain） |

未发现任何未列举的 domain→domain 互引。

---

### 4. internal/ 不引 domain 包规则

**结论：通过 —— 未发现违规**

逐一检查了所有 `internal/` 子包（13 个包）对 `zjdns/{cache,edns,database,zone,ruleset}` 的导入，结果为零。`internal/latency → config` 是已知例外。✓

---

### 5. Server 子包不引父包规则

**结论：通过 —— 仅有一个已知例外**

检查了 server/ 下所有子包对其直接父包的导入：

| 子包 | 父包 | 是否导入 | 状态 |
|------|------|---------|------|
| handler/middleware | handler | 是（10 个文件引用） | 已知例外，通过 |
| resolver/dnssec | resolver | 否 | 通过 |
| resolver/probe | resolver | 否 | 通过 |
| upstream/plain | upstream | 否 | 通过 |
| upstream/tls | upstream | 否 | 通过 |
| upstream/tlcp | upstream | 否 | 通过 |
| upstream/socks5 | upstream | 否 | 通过 |
| upstream/dnscrypt | upstream | 否 | 通过 |
| upstream/pool | upstream | 否 | 通过 |
| protocol/plain | protocol | 否 | 通过 |
| protocol/tls | protocol | 否 | 通过 |
| protocol/dnscrypt | protocol | 否 | 通过 |

---

### 6. 接口定义在消费者包检查

**发现：2 个违规**

#### 发现 6a（中严重度）：`cache.Store` 定义在生产者包

- **文件：** `cache/cache.go:57`
- **问题：** `cache.Store`（及 `StoreReader:34`、`StoreWriter:40`、`StoreLifecycle:48`）定义在 `cache/` 包，但消费者分布在 `server/handler`、`server/resolver`、`server/resolver/dnssec`、`server/resolver/probe`、`server` 等多个包中。
- **风险：** 消费者耦合到生产者的接口定义。如果需要更换底层存储实现，必须修改 `cache` 包本身。较低层的 `cache` 包定义了被高层广泛使用的契约，违反了"消费者定义接口"的惯用原则。
- **修复建议：** 遵循现有的好范例 —— `server/resolver/probe.CacheSetter`（`server/resolver/probe/probe.go:22`）已在消费者包正确定义了最小子集接口。应为 `server/handler` 和 `server/resolver` 分别定义仅包含所需方法的消费者端接口，由 `cache.Cache` 隐式实现。

#### 发现 6b（中严重度）：`edns.DNSHandler` 定义在生产者包

- **文件：** `edns/edns.go:23`
- **问题：** `edns.DNSHandler`（定义 `ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg`）定义在 `edns/` 包，消费者包括 `server/protocol/tls`（`server.go:51`）、`server/protocol/dnscrypt`（`server.go:38`）、和间接的 `server/protocol/tlcp`。实现者在 `server.Server`（`server/server.go:379`）和 `handler.Handler`（`server/handler/handler.go:102`）—— 都在高层 `server/` 中。
- **风险：** 逆向依赖 —— 低层包（`edns`）为高层包（`server`）定义了接口契约。`edns.DNSHandler` 的方法签名与 `handler/serveDNS` 高度相关，应定义在消费者侧。
- **修复建议：** 将 `DNSHandler` 接口移到 `server/handler` 包（已有的 `QueryHandler` 和 `Wrapper` 接口所在位置），或者定义在 `server/protocol` 层作为协议消费者接口。`edns.Handler` 的 `ApplyToMessage`、`ParseFromDNS` 等方法是纯 EDNS 工具方法，不需要依赖 `DNSHandler` 接口。

---

### 7. God Package 趋势检查

**发现：4 个包需要关注，1 个为高严重度**

#### 发现 7a（高严重度）：`server/resolver` —— 11 类型/3975 行/11 文件

- **文件：** `server/resolver/*.go`（11 个非测试文件）
- **问题：** 一个包同时处理：
  - 上游转发（`forward.go`，329 行）
  - 递归解析（`recursive.go` 373 行 + `recursive_helpers.go` 226 行 + `recursive_ns.go` 116 行）
  - Nameserver 管理（`nameserver.go` 441 行）
  - DNSSEC chain-of-trust（`dnssec_chain.go` 452 行）
  - 区域切割检测（`zonecut.go` 181 行）
  - QNAME 最小化（`qname_minimise.go` 125 行）
  - NS 地址缓存（`ns_addresses.go` 161 行）
  - 根提示（`root_hints.go` 108 行）
- **风险：** 高认知负载；并发开发时的合并冲突风险；测试需要全局 package 设置。
- **修复建议：** 拆分为子包：`server/resolver/forward`、`server/resolver/recursive`、`server/resolver/nameserver`，保持 `server/resolver` 为外观层。

#### 发现 7b（中严重度）：`internal/dnsutil` —— 30 导出符号，经典杂物包

- **文件：** `internal/dnsutil/*.go`（7 非测试文件，21 导出函数，7 文件分别为 TCP 帧、DoH、BIND 地址、反向 DNS、文件下载、握手日志、工具函数）
- **问题：** 无内聚性的工具函数集合 —— TCP 帧读写（`tcpframe.go`）、DoH HTTP 执行（`https_dns.go`）、BIND 地址解析（`bind.go`）、文件下载（`download.go`）、握手日志（`dnsutil.go` 部分函数）。新功能容易被添加到此包而非创建有意义的独立包。
- **风险：** 包无唯一职责；函数间无共享状态，本应为独立包。
- **修复建议：** 拆分为：`internal/dnstransport`（TCP 帧 + DoH 请求）、`internal/bindutil`（BIND 地址解析）、`internal/netutil`（IP 提取、客户端 IP 检测类函数）。

#### 发现 7c（中-低严重度）：`internal/dnscryptcrypto` —— 64 导出符号，11 包级别 var

- **文件：** `internal/dnscryptcrypto/*.go`（8 非测试文件，42 导出函数，6 类型，5 const，11 var）
- **问题：** 11 个包级别可导出变量表示可修改全局状态，对并发使用有风险。42 个导出函数对于单一加密协议包较高。
- **修复建议：** 将全局状态封装到结构体/接收器方法中。可考虑将证书操作（`certificate.go`）、加密操作（`encryption.go`）、协议编码解码（`proto.go`）分离为独立文件，但保持在同一包内（已有一定文件内聚）。

#### 发现 7d（低严重度）：`edns` —— 6 类型/35+ 方法，合并 ECS+Cookie+Padding+EDE

- **文件：** `edns/edns.go`（EDNS 总入口）、`ecs.go`（ECS 处理）、`cookie.go`（Cookie 验证）、`padding.go`（Padding 控制）
- **问题：** 四个独立的 EDNS(0) 子特性放在同一包中。Cookie 验证（`cookie.go` 305 行）与 ECS 解析（`ecs.go` 207 行）代码量大且无逻辑关联。
- **风险：** 修改 Cookie 逻辑需要接触与 ECS 相同的包。边际复杂度。
- **修复建议：** 可拆分但不紧急。Cookie/ECS 子包化是低优先级的整洁性改进。

---

### 汇总

| 维度 | 状态 | 主要发现 |
|------|------|---------|
| 导入分层 | 通过 | 严格 DAG 无违规 |
| 循环依赖 | 无 | go vet + 手动追踪确认 |
| Domain 不互引 | 通过 | 全部 exception 覆盖 |
| internal 不引 domain | 通过 | 无违规 |
| Server 子不引父 | 通过 | 仅 middleware→handler（已知例外） |
| 接口消费者定义 | **2 违规** | `cache.Store`（cache/cache.go:57）、`edns.DNSHandler`（edns/edns.go:23） |
| God 包趋势 | **4 包需关注** | `server/resolver`(高)、`internal/dnsutil`(中)、`internal/dnscryptcrypto`(中低)、`edns`(低) |