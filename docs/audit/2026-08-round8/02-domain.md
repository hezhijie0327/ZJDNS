# Domain 组审计 — config / cache / edns / zone / ruleset / stats（24 文件，双份独立审计合并）

## HIGH

### H1: cache/ptr.go:47-52, 87 — PTR 索引共享切片竞态（见综合报告 H1）
- `updatePtrIndex` 锁外 `append(old, owner)` 就地写 lrumap.Get 返回的共享底层数组；并发同 IP 时 owner 映射互相覆盖丢失 + 写-写竞态；`cleanupPtrIndex` 的 `kept := keys[:0]` 在 Range 锁内就地压缩，锁挡不住已在锁外遍历旧切片头的 `ReverseLookup`（ptr.go:121）。
- 修复：`append(slices.Clone(old), owner)` + `make([]entryKey, 0, len(keys))` 复制式过滤；补 -race 并发测试（现有 BenchmarkStoreParallel 只测 store 不测索引）。
- 关联：lrumap 无原子 RMW/Update API——派生索引维护的读-改-写非原子是本轮唯一 HIGH 根因。

## MEDIUM（8 项）

| # | 位置 | 描述 |
|---|------|------|
| M1 | cache/store.go:93 → ptr.go:86-97 | OnEvict 在 store 写锁内对 ptrIndex **全表 Range 扫描**（每淘汰 O(P)，16MB 预算下数万 IP key）；满缓存 churn 时每次 Set 支付全表扫描。修复：cacheEntry 加 `inIndex` 标记 O(1) 短路，或延迟清扫。 |
| M2 | cache/store.go:363-389 | `ecsFallbackCandidates` 每次 Get（含无 ECS 查询）构造 3 元素切片字面量 + 最多 3 次 maskIP 堆分配——热路径每查询分配。修复：无 ECS 分支返回包级只读切片。 |
| M3 | cache/store.go:200-204 + answer_sort.go:51-73 | A/AAAA 命中且 Answer>1 时每查询分配 2 个 map + 最多 64 次 latency.Get 锁操作——命中路径分配多于 miss 路径。 |
| M4 | zone/zone.go:253-255 | `exactKey` 用 `fmt.Sprintf("%s\|%d\|%d")`——Evaluate 每查询最多 34 次堆分配（exact+sentinel+16 wildcard 后缀 ×2）。修复：结构体 key 或 strings.Builder 复用。 |
| M5 | config/validate.go:186-190 | URL 解析成功但 scheme/host 为空时 `fmt.Errorf("...: %w", err)` 包装 **nil error** → `%!w(<nil>)` 误导消息；`hpErr`（真正的错误）被丢弃。 |
| M6 | stats/stats.go:84-133 | Record 的 result/协议魔法字符串（"hit"/"udp"/"tls"...）未提取常量，调用方裸字面量传参——拼错静默丢计数（switch 无 default）。 |
| M7 | edns/padding.go:45-57 | 每个需填充的加密消息**打包两次**（测压缩尺寸 + 发送）+ 每次调用 crypto/rand.Read 一次 syscall——DoT/DoQ/DoH 热路径；`_, _ = rand.Read` 无注释。修复：msg.Len() 近似；padding 用 math/rand（非密码学用途）。 |
| M8 | config/ddr.go:143-150 | 注释称 "drop this protocol definition entirely" 但 `r.alpns[d.alpn] = true` 已在上方执行，`continue` 是空操作——HTTPS 端口可能以 `alpn=h2` 无 dohpath 发布，广告了错误的端点。 |

## LOW（25 项）

| 位置 | 描述 |
|------|------|
| config/load.go:118-126 | resolveStamp switch 的 default 与 case 行为完全重复——可简化为无条件赋值。 |
| config/validate.go:230-234 | proxy 端口检查硬编码 65535 而非 `MaxPortNumber`（同文件 29 行已用）。 |
| config/ecs.go:126-152 | UnmarshalJSON 对 `null` 与 `{}` 的 PreferIPv4 默认值不一致（null 分支不应用默认值）。 |
| config/config.go:227-232 | `IsRecursive()` 大小写敏感比较；"Recursive" 配置报误导性 "address invalid"。 |
| config/validate.go:186-190 | HTTPS 上游仅检查 `u.Scheme != ""`——"http://" 可通过验证（明文降级）。 |
| config/validate.go:265 | `strings.Contains(dir, "..")` 判定路径穿越——合法目录名 `a..b` 被误拒。 |
| config/validate.go:237-242 | `!` 前缀处理只剥一个——"!!foo" 与 zone parseMatchTags 的解释不一致。 |
| cache/lifecycle.go:54-57 | `_, _ = c.Clear()` 丢弃错误无注释。 |
| cache/codec.go:137-143 | ptrCodec.EncodeValue 的 key 数 `uint16` 截断无防御（>65535 entryKey 时文件损坏）。 |
| cache/cache.go:38-44 | Store 接口注释残留 "., composed from its role" 编辑残片。 |
| cache/ptr.go:135-151 | ReverseLookup 对同一 entry 内多个同 IP RR 重复追加同名结果——需 seen-map 去重。 |
| cache/store.go:33,255-257 | `expiresAt` 硬删除期限仅用于 Save Keep 过滤，内存中无过期清扫——死条目占预算至 LRU 压力。 |
| cache/lifecycle.go:132-136 | `SetPtrPersist` 仅当 Len()==0 时重建索引；崩溃于 Manager SaveAll 中间（cache.zst 已写 ptr.zst 未写）时重启后**陈旧索引静默不重建**。 |
| zone/parse.go:63-77 | flush 内每个 (type,class) group 重复打包 authority/additional N 次（加载路径）。 |
| zone/parse.go:268-287 | tokenize 对未闭合引号行静默接受。 |
| zone/parse.go:177-178 | 垃圾行静默 continue（坏记录行有 warn，此处无）。 |
| zone/wire.go:119-131 | RFC 3597 分支不校验 `len(fields[1]) == 2*len`——声明长度与数据不符时打包畸形 wire 记录。 |
| zone/zone.go:39,354 | `Result.cachable` 字段只写从未读。 |
| zone/zone.go:266 | 长度检查在 `dnsutil.Canonical` 之前对原始 qname 执行——253 字符无点 qname 与带点 254 行为不一致。 |
| zone/zone.go:428 | `evalDynamic` 用 `strconv.Quote` 生成 TXT rdata，与 chaos.go:89-92 注释指出的 Go 转义陷阱自相矛盾。 |
| edns/ecs.go:191-200 | `detectVia` 的 `allowFallback` 参数恒为 false（唯一调用点传 false）。 |
| stats/stats.go:103-106 | prefetch 计入 total/totalMS 但排除出延迟桶——hit/miss 百分比分母与 p50/p95 分母不一致。 |
| stats/persist.go:141-144 | merge 长度检查硬编码 `27+24+latBuckets+1` 魔法数字，与 snapshot 字段顺序手工耦合。 |
| edns/padding.go:57 | `_` 丢弃 rand.Read 错误无注释（计入 M7）。 |
| config/ddr.go:143-150 | （并入 M8）。 |

## 已排除疑点（有代码证据安全）

- cache/codec.go：全部边界检查 + round-trip 测试齐备。
- edns/cookie.go：RFC 9018 时间窗与 RFC 1982 序列算术正确（含官方测试向量）。
- edns/edns.go：DO 镜像经 fork SetReply 正确拷贝 Security。
- ruleset/iptrie.go：IPv4/IPv6 共享映射与 depth-96 隔离正确。
- stats/persist.go：挂载顺序（先 assign store 再 enablePersist）、merge 边界正确。
- zone/ruleset WORM 并发：LoadRules 仅启动时经 server.go:134 调用一次，无运行时重载。
- config/defaults.go：无跨包重复常量（grep 验证）。
