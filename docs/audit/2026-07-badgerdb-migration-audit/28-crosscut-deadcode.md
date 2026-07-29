# 28 · 交叉分析：死代码

> 审计 Agent：Phase 2a · DeadCode
> 范围：全项目未用符号、重复代码、不必要接口


以下是对 ZJDNS 项目中死代码的搜索发现汇总。搜索条件：排除 `_test.go` 和 `vendor/`。

---

## 发现 1：未使用的导出常量 (3 处)

### 1.1 `config.DefaultPendingCleanupInterval`
- **文件**: `config/defaults.go:111`
- **严重程度**: 低
- **描述**: 该常量定义为 `60 * time.Second`，并带有注释 "singleflight orphan-entry cleanup ticker"，但从未在代码中引用。
- **风险**: 无运行时风险；增加了认知负荷，使维护者误以为已有清理机制。
- **修复建议**: 删除该常量，或在实现单播孤立条目清理时按需实现该 ticker。

### 1.2 `config.PrivacyProfileOpportunistic`
- **文件**: `config/defaults.go:228`
- **严重程度**: 低
- **描述**: 常量定义值为 `"opportunistic"`。其兄弟常量 `PrivacyProfileStrict`（`"strict"`）在 `config/validate.go:207` 中被使用，但 `PrivacyProfileOpportunistic` 在任何地方都未被引用。同一个字符串值在 `config/validate.go:205` 的注释中写死。
- **风险**: 无；字符串字面量在验证逻辑中通过字符串比较而非通过该常量匹配。
- **修复建议**: 从此常量变为引用它，或直接删除此常量并内联字面量。

### 1.3 `config.SOCKS5MaxAuthLen`
- **文件**: `config/defaults.go:300`
- **严重程度**: 低
- **描述**: 定义为 `255`（RFC 1929 最大用户名/密码长度），但代码中任何地方都未使用。SOCKS5 认证处理中未对用户名/密码长度进行校验。
- **风险**: 极低；该常量为文档性质，但无强制执行。
- **修复建议**: 若 SOCKS5 认证代码经过审计认为无需长度校验，则删除此常量；否则将其接入实际校验。

---

## 发现 2：重复代码

### 2.1 TCP Keep-Alive 监听器实现重复
- **文件**: 
  - `server/protocol/tlcp/tlcp.go:18-33`（私有类型 `tcpKeepAliveListener`）
  - `internal/dnsutil/keepalive.go:11-31`（导出类型 `TCPKeepAliveListener`）
- **严重程度**: 中
- **描述**: TLCP 包定义了自己的私有 `tcpKeepAliveListener`，功能和 `internal/dnsutil.TCPKeepAliveListener` 完全相同——包装一个 `net.Listener`，在 Accept 时设置 TCP Keep-Alive。TLCP 版本有两行变体：它使用 `config.DefaultTCPKeepAlivePeriod`（从 config 导入），而 dnsutil 版本内联了自己的 `defaultTCPKeepAlivePeriod = 30 * time.Second`（由于分层限制无法导入 config）。
- **风险**: 低；功能相同。维护两个副本增加了一致性风险——若 dnsutil 版本更新，TLCP 版本可能过时。
- **修复建议**: 要么让 TLCP 的 `startDOTServer` 使用 `dnsutil.TCPKeepAliveListener`，要么将共享实现提取到 `dnsutil` 包中，并允许通过正确导入 config 包等方式传递周期参数。

### 2.2 内联的 DNS 消息构建模式（潜在重复）
- **文件**: 多个位置，特别是 `server/protocol/tls/quic.go:23-78` 和 `server/protocol/tls/http3.go:18-98`
- **严重程度**: 低
- **描述**: `startDOQServer()` 和 `startDOH3Server()` 共享约 40 行近乎相同的 QUIC 服务器启动代码（地址解析、QUIC 配置结构体、UDP 监听、传输设置、ListenEarly），仅在后续处理上有所不同（DOQ 使用流处理器，DoH3 使用 http3.Server ServeQUICConn）。
- **风险**: 低；功能独立。若引入替代的 QUIC 监听器配置，重复可能引起问题。
- **修复建议**: 考虑将公共 QUIC 设置部分提取到一个共享的 `startQUICServer(port, nextProtos, handler)` 辅助函数中，或保持原样——差异足够小，提取可能显得过度设计。

---

## 发现 3：不必要的接口拆分

### 3.1 `StoreReader`、`StoreWriter`、`StoreLifecycle`
- **文件**: `cache/cache.go:32`、`:40`、`:48`
- **严重程度**: 低
- **描述**: 这三个接口将 `Store` 接口按读/写/生命周期划分为子集。但在整个代码库中，没有任何消费者使用这些子接口作为参数类型或变量类型——所有使用者都以 `cache.Store`（完整的组合接口）作为依赖。
- **风险**: 无运行时风险。增加了接口面，但无任何消费者利用该拆分。
- **修复建议**: 若代码审查认为细粒度接口有助于单元测试，则保留；否则可将它们折叠到单独的 `Store` 接口中。

---

## 搜索摘要

| 类别 | 发现数量 | 严重程度 |
|---|---|---|
| 未使用的导出常量 | 3 | 低 |
| 重复代码 | 2 | 中/低 |
| 不必要的接口 | 1（3 个接口） | 低 |
| 未使用的导入 | 0 | — |
| 注释掉的代码段 | 0 | — |
| 未使用的导出函数/类型/变量 | 0（由 `golangci-lint unused` 确认） | — |
| 单实现接口（默认必需） | 0 处死代码（按设计） | — |

**结论**：该代码库总体上很整洁——`golangci-lint -E unused` 未报告任何问题。主要发现是 3 个从未被引用的导出常量，以及 TLCP 包中一个重复的 TCP Keep-Alive 监听器类型。这两种情况都不构成安全或正确性问题，但有代码卫生方面的益处。