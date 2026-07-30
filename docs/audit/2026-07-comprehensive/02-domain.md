# Domain 层审计报告 — `config` / `database` / `cache` / `edns` / `zone` / `ruleset`

## 审计范围

22 个源文件

## 发现

### MEDIUM

#### M1. padding.go 双重 Pack

- **文件**: `edns/padding.go:40`
- **类别**: performance
- **问题**: `addPadding` 调用 `msg.Pack()` 计算压缩大小以进行填充计算。消息在发送时再次 Pack。每个响应两次完整 Pack。注释（L37-39）承认此权衡但实现成本高。
- **修复**: 缓存打包结果并复用。

#### M2. cache.Set 静默 Pack 失败

- **文件**: `cache/store.go:233-236`
- **类别**: error-handling
- **问题**: `msg.Pack()` 失败时错误被静默丢弃，`msgWire` 仍为 nil。继续在 BadgerDB 中存储空线格式负载条目——检索时永远 miss，浪费 DB 空间。
- **修复**: 记录 Warn 并跳过存储。

#### M3. padding.go 阻塞式 crypto/rand.Read

- **文件**: `edns/padding.go:46`
- **类别**: performance
- **问题**: 每个填充响应调用 `crypto/rand.Read`。Linux 上使用 `getrandom(2)`，若熵池未初始化则阻塞。填充字节不需要加密级随机性（RFC 8467 不要求）。
- **修复**: 使用 `math/rand/v2`（Go 1.22+，非阻塞）。

### LOW

#### L1. additional 双重 clone

- **文件**: `cache/store.go:221,226`
- **类别**: performance
- **问题**: `additional` 切片在每次 Set 调用中 clone 两次。第一次 clone 完全浪费。
- **修复**: 重构为单次 clone。

#### L2. 空协议产生误导性错误

- **文件**: `config/validate.go:162-183`
- **类别**: code-quality
- **修复**: 添加显式协议非空检查。

#### L3. ecsFallbackCandidates 每次 Get 都分配

- **文件**: `cache/store.go:329-349`
- **类别**: performance
- **修复**: 使用栈分配数组代替堆分配切片。

#### L4. DNSHandler 重复注释

- **文件**: `edns/edns.go:17-23`
- **类别**: docs
- **修复**: 合并为单个注释块。

### 维度合规

| 维度 | 状态 |
|------|------|
| 代码质量 | ⚠️ L2 |
| 性能 | ⚠️ M1, M3, L1, L3 |
| 错误处理 | ⚠️ M2 |
| 文档质量 | ⚠️ L4 |
| 其余 | ✅ |
