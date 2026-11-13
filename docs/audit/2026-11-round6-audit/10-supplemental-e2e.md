# Round 6 补充验证 — 域名列表真实解析 / A/B 压测 / 防污染矩阵 / 全 debug 配置覆盖(2026-11-14)

用户质询驱动的补充验证（"域名列表真实解析过了吗？有性能回归吗？docs/debug 配置都做过吗？防污染质量有没有下降？"）。

## 1. docs/debug/domains.txt 真实解析（186 域名，递归模式真网）

| 二进制 | OK | FAIL |
|--------|----|----|
| 修复前 88de480b | 165 | 21 |
| 修复后 v4.8.27 | 165 | 21 |

失败集合 **完全一致**（diff 为空）——21 个失败为真实世界死域/被墙域，与代码无关。解析零回归。

## 2. A/B 压测（domains.txt 轮转 186 域名，workers=16×12s/协议）

| 协议 | old qps | new qps | Δ |
|------|---------|---------|---|
| udp | 41186 | 40125 | -2.6% |
| tcp | 42095 | 43292 | +2.8% |
| tls | 41437 | 42814 | +3.3% |
| quic | 38488 | 37304 | -3.1% |
| https | 39499 | 38105 | -3.5% |
| tlcp | 41544 | 41106 | -1.1% |
| dnscrypt | 23105 | 22837 | -1.2% |

全部在 ±3.5% 噪声带；avg 延迟同带（0.37-0.43ms）。复跑（new2/old2 交替）：udp 由 -2.6% 翻为 +4.6%，https 由 -3.5% 收窄为 -1.9%——**交替翻转证实为机器噪声，无真实回归**。TLCP 写合并（P4）在 tls/tlcp 上的 +3% 方向性改善与 bench 一致。

## 3. 防污染质量（docs/poc/interception 确定性注入测试台）

**发现并修复测试台自身 bug**：rig 的真实应答在 DO=1 查询下静默 pack 失败（手动 OPT + fork Pack 自动物化 OPT 重复）——修 docs/poc/interception/main.go（去掉手动 OPT）。修复前 rig 对任何 ZJDNS 二进制都只发假包（矩阵全 other），修复后矩阵有效。

矩阵（100 查询/格，unique qnames，`skip_cache`）：

| 配置 | old (88de480b) | new (v4.8.27) |
|------|----------------|---------------|
| spoofguard 单开 × bare | 100 拦截 / 0 泄漏 | 100 / 0 |
| hopguard 单开（arm=64）× bare | 100 / 0 | 100 / 0 |
| capsguard 单开 × blind | 100 / 0 | 100 / 0 |
| 三守卫全开 × bare | 100 / 0 | 100 / 0 |
| 三守卫全开 × blind | 100 / 0 | 100 / 0 |
| 三守卫全开 × fake-edns | 98 / 0 / 2 other | **100 / 0 / 0** |
| 无守卫基线 | 0 / 100 泄漏 | 0 / 100 泄漏 |

**新二进制不降反升**：full-edns 威胁模型下旧版 2 次"other"（SERVFAIL，未确证分歧 fail-closed 的代价）被 S1/S2 修复消除为 100% 服务真实应答。滴注攻击（S2 模型）不在 rig 形态内，由新增单测 TestExecuteUDPCollect_DripDeadlineNotServed 覆盖。

## 4. docs/debug/ 配置全覆盖

| 子目录 | 配置 | 结果 |
|--------|------|------|
| defense/ | spoofguard / hopguard / hopguard-spoofguard / splitguard / poisonguard / recursive-defense | 6/6 PASS（真网串行验证） |
| defense/ | spoofguard-socks5 | PASS（自建最小 SOCKS5 UDP-ASSOCIATE 代理补上环境：调试出三个代理侧 bug——握手 PORT 解析顺序、relay 出站回程泵缺失、parseAddr ATYP 偏移——后 spoofguard 经 relay fast-return 正常；代理已收编 docs/debug/socks5srv 并更新 DEBUG.md 失效命令） |
| upstream/ | alidns-{https,http3,quic,tls} / dnspod-http-tlcp / quad9-dnscrypt / fallback | 7/7 PASS |
| dnscrypt/ | proxy-pq（X-Wing） / proxy-classic（XChacha20） / proxy-classic-ephemeral | 3/3 PASS（真实互操作，dnscrypt-proxy 源码构建） |
| routedns/ | dtls-client.toml | PASS（RouteDNS 源码构建，DTLS 1.2 互操作；CA 证书按文档流程预生成） |
| rfc8998/ | smpeer client / doh / server 三模式 | PASS（TLS_SM4_GCM_SM3 + CurveSM2 双向协商） |
| loopback/ | 14 专用口 + 7 共享口 + MQTYPE×3 + 递归 | 前轮已过 |

## 5. QUIC 端口残留事故记录

复测轮 QUIC 全挂（ok=0）——定位为前轮压测进程未退净占用 UDP 10784（lsof 证实），清场后 fail=0 / 34.8k qps。方法论：压测脚本必须 pgrep+lsof 清场（已有"测试台状态泄漏"条目的实例）。
