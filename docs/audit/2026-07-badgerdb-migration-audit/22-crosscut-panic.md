# 22 · 交叉分析：Panic 检测

> 审计 Agent：Phase 2a · Panic
> 范围：全项目 nil 解引用、切片越界、空 map 写入、裸类型断言


---

## ZJDNS 恐慌模式审计报告

审计范围：`zjdns/` 下全部 146 个非测试 `.go` 文件，排除 `*_test.go`。涵盖 7 类模式。

---

### 摘要

| 类别 | 已检查 | 发现问题 |
|---|---|---|
| 裸类型断言 (无 comma-ok) | 70 处 `.()` 表达式 | 2 处高风险 |
| nil map 写入 | ~50 处 map/slice 索引赋值 | 0 处 |
| slice 越界访问 | ~60 处 `[0]` / `[i]` | 0 处 (全部有守卫) |
| nil 指针解引用 | ~100 处指针字段访问 | 9 处 (均为 nil RR) |
| channel 操作 | 35 处 `close()` | 0 处 (全部有 sync.Once 或单次关闭) |
| 除零/模零 | ~10 处 `%` / `/` | 0 处 (全部有零值守卫) |
| defer/recover | 80+ 处 HandlePanic | 0 处 (全部正确) |

**总计：11 项发现**，风险等级：2 高 + 9 中。

---

### 发现 #1 — 裸类型断言：`key.(string)` 可能 panic

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/tasks.go:116`  
**严重程度：** 高  
**问题：** `sync.Map.Range` 回调中，`key` 是 `any` 类型，直接 `key.(string)` 是裸断言。如果 map 被写入非 `string` 类型的键，触发 panic。  
**风险：** 当前代码路径中所有键来源于 `w.RemoteAddr().String()`（始终是 string），但 map 通过 `sync.Map` 无类型约束。  
**修复：** 改用逗号-ok 模式：`keyStr, ok := key.(string); if !ok { ... }`

---

### 发现 #2 — 裸类型断言：`ed25519.PublicKey` 裸断言

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/dnscrypt/server.go:355`  
**严重程度：** 中  
**问题：** `s.signingSK.Public().(ed25519.PublicKey)` 是裸断言。`signingSK` 类型为 `ed25519.PrivateKey`，其 `Public()` 方法保证返回 `ed25519.PublicKey`。  
**风险：** 实践中安全（标准库契约保证），但风格上违反防御式编程原则。  
**修复：** 增加逗号-ok 检查或将为变量声明类型约束。

---

### 发现 #3 — nil RR 解引用：`Validate()` 中无 nil 守卫

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/defense/poisonguard.go:83`  
**严重程度：** 中  
**问题：** `for _, rr := range response.Answer { dnsutil.Canonical(rr.Header().Name) ... }` — 如果 `response.Answer` 包含 nil 元素，`rr.Header()` 触发 nil 解引用 panic。  
**风险：** `miekg/dns` 从线格式解析不会产生 nil RR，但程序构造的消息可能引入 nil；`HandlePanic` 不覆盖此路径。  
**修复：** 循环体内加 `if rr == nil { continue }`。

---

### 发现 #4 — nil RR 解引用：`IsPoisonedByTLD()` 中无 nil 守卫

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/defense/poisonguard.go:107`  
**严重程度：** 中  
**问题：** 同上模式：`for _, rr := range response.Answer { dnsutil.Canonical(rr.Header().Name) ... }` 无 nil 守卫。  
**风险：** 同上。  
**修复：** 循环体内加 `if rr == nil { continue }`。

---

### 发现 #5 — nil RR 解引用：CNAME 链处理中无 nil 守卫

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/recursive.go:335`  
**严重程度：** 中  
**问题：** `for _, rr := range qr.Answer { h := rr.Header() ... }` 无 nil 守卫。  
**风险：** 如果 `qr.Answer` 包含 nil 元素，panic。  
**修复：** 循环体内加 `if rr == nil { continue }`。

---

### 发现 #6 — nil RR 解引用：CNAME 链第二个循环中无 nil 守卫

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/recursive.go:346`  
**严重程度：** 中  
**问题：** `for _, r := range qr.Answer { if cname, ok := r.(*dns.CNAME); ok { strings.EqualFold(r.Header().Name, ...) } }` — `r` 可能在 `r.Header()` 处为 nil。  
**风险：** 同上。注意类型断言 `r.(*dns.CNAME)` 对 nil 接口不会 panic（返回 `nil, false`），但后续的 `r.Header()` 在 `if ok` 块外无条件执行。  
**修复：** 循环体内加 `if r == nil { continue }` 或将 `Header()` 调用移入 `if ok` 块内。

---

### 发现 #7 — nil RR 解引用：`CapValidatedTTL` 中无 nil 守卫

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/dnssec/nsec.go:247`  
**严重程度：** 中  
**问题：** 第二个循环 `for _, rr := range sections { ... hdr := rr.Header() }` — `sections` 为 `[][]dns.RR{answer, authority, additional}`，可能有 nil RR 未被第一个循环过滤（第一个循环仅过滤 RRSIG 类型）。  
**风险：** 如一个 section 包含非 RRSIG 的 nil RR，`rr.Header()` 触发 panic。  
**修复：** 第二个循环内加 `if rr == nil { continue }`。

---

### 发现 #8 — nil RR 解引用：`processRR` 中 `rr.Clone()` 可能 panic

**文件：** `/Users/hezhijie/Downloads/ZJDNS/cache/cache.go:122`  
**严重程度：** 中  
**问题：** `processRR(rr dns.RR, ...)` — 调用 `rr.Clone()` 前没有 nil 守卫。当 `rr` 为 nil 且 `!includeDNSSEC` 为 false 或类型 switch 未匹配时触发 panic。  
**风险：** `processRR` 被 `ProcessRecords` 调用，输入为 cache entry 的 RR 切片。  
**修复：** 在函数开头加 `if rr == nil { return nil }`。

---

### 发现 #9 — nil RR 解引用：`cloneRRs` 中 `rr.Clone()` 可能 panic

**文件：** `/Users/hezhijie/Downloads/ZJDNS/cache/cache.go:182`  
**严重程度：** 中  
**问题：** `for i, rr := range rrs { out[i] = rr.Clone() }` — 如果 `rrs` 包含 nil RR，`rr.Clone()` 在 nil 接口值上调用，触发 panic。  
**风险：** 输入来自 cache entry 或上游响应。  
**修复：** 循环体内加 `if rr == nil { continue }`。

---

### 发现 #10 — nil RR 解引用：`stripOPT` 中 `dns.RRToType(nil)` 可能 panic

**文件：** `/Users/hezhijie/Downloads/ZJDNS/cache/store.go:367`  
**严重程度：** 中  
**问题：** `for _, rr := range rrs { if dns.RRToType(rr) != dns.TypeOPT { ... } }` — `dns.RRToType` 内部调用 `rr.Header()`，nil RR 导致 panic。  
**风险：** `stripOPT` 的输入来自 `cloneRRs` 输出（可能已包含 nil 条目）或 cache entry。  
**修复：** 循环体内加 `if rr == nil { continue }`。

---

### 发现 #11 — nil RR 解引用 / slice 索引：`cacheGlueRecords` 中 `records[0]` 可能为 nil

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/recursive_ns.go:108`  
**严重程度：** 中  
**问题：** `if len(records) > 0 { qtype := dns.RRToType(records[0]) }` — 守卫保证不越界，但 `records[0]` 可能为 nil 注册的 RR，导致 `dns.RRToType(nil)` panic。  
**风险：** 胶水记录来自 `response.Extra`，正常解析不应有 nil，但程序构造可能引入。  
**修复：** 加 `records[0] != nil` 守卫。

---

### 未发现问题的模式说明

| 模式 | 说明 |
|---|---|
| **map 写 nil 恐慌** | 所有 `map` 变量在写入前都通过 `make()` 或在创建结构体时初始化。`var tags map[string]bool` 模式的写入前均有 `if tags == nil { tags = make(...) }` 守卫。 |
| **slice 索引越界** | 所有 `Question[0]` 访问由 `handler.go:109` 和 `validation.go:23` 守卫；其他 `[i]` 访问均有 `len()` 检查。`network[0]` 由 `network != ""` 守卫。 |
| **channel 关闭/发送** | 所有 `close()` 由 `sync.Once` 保护或为单次关闭。`Record()` 中有 `recover()` 捕获已关闭 channel 的发送。 |
| **除零/模零** | `% n` 前有 `n <= 0` 检查；`% staleTTL` 前有 `staleTTL == 0` 检查；`% origTTL` 前有 `origTTL <= 0`；`% remainingSteps` 前有 `remainingSteps <= 0`；`% len(servers)` 前有 `len(servers) == 0` 守卫。 |
| **defer/recover** | `HandlePanic()` 实现正确（`recover()` → 日志+堆栈）；3 个直接 `recover()` 全部包裹在 `defer` 中。 |