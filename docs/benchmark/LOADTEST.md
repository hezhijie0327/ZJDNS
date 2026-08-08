# 全协议压测指南（LOADTEST）

本指南描述如何对 ZJDNS 做**全协议负载压测**并分析瓶颈 / 泄漏。压测工具 `benchclient`
复用生产代码路径（`server/upstream.Client` —— 与真实转发/递归流量相同的出口），
服务端与客户端各开一个 pprof 端点，可同时抓取两侧 profile 做对照分析。

这套方法曾发现并修复过三个真实问题（见文末「已发现问题」），可直接复用。

## 目录

- [1. 环境准备](#1-环境准备)
- [2. 服务端配置与启动](#2-服务端配置与启动)
- [3. 客户端构建与用法](#3-客户端构建与用法)
- [4. pprof 采集](#4-pprof-采集)
- [5. 分析流程](#5-分析流程)
- [6. 已发现问题（参考）](#6-已发现问题参考)

## 1. 环境准备

```bash
# 构建 ZJDNS 服务端
go build -o /tmp/zjdns-server ./cmd/zjdns

# 构建压测客户端
go build -o /tmp/benchclient ./docs/benchmark/loadtest

# 可选：UDP/TCP 对照压测（C 程序，高并发友好）
brew install dnsperf
```

## 2. 服务端配置与启动

压测服务端需要：**全协议监听 + pprof + zone 静态规则**。zone 规则让查询完全走本地
处理（无外网依赖），纯粹压测协议栈与服务端管线。

```bash
mkdir -p /tmp/zjdns-bench && cat > /tmp/zjdns-bench/server.json << 'EOF'
{
  "server": {
    "pprof": "6060",
    "log_level": "error",
    "protocol": {
      "udp": "10533", "tcp": "10533", "tls": "10853", "quic": "10784",
      "https": { "port": "10443", "endpoint": "/dns-query" },
      "http3": { "port": "10444", "endpoint": "/dns-query" },
      "dtls": "10434", "dnscrypt": "12443", "tlcp": "10850",
      "http_tlcp": { "port": "10440", "endpoint": "/dns-query" },
      "dtlcp": "8542"
    },
    "certificate": {
      "domain": "zjdns-test.local",
      "tls": { "self_signed": true },
      "tlcp": { "self_signed": true },
      "dnscrypt": {
        "private_key": "BC1F1237E602BAF1F302329495008EC8A662AC33444A191E3CC4A8B44583D3BE1498ACC39ABEA9A0102FA655DA6BE74084CEF4AFC9992E43FDAE364ED156DE53",
        "public_key": "1498ACC39ABEA9A0102FA655DA6BE74084CEF4AFC9992E43FDAE364ED156DE53"
      }
    },
    "zone": [
      { "name": "www.bench.test", "answer": [ { "type": 1, "ttl": 3600, "content": "1.2.3.4" } ] }
    ],
    "features": { "cache": {} }
  },
  "upstream": [{ "address": "223.5.5.5:53", "protocol": "udp" }]
}
EOF

# 启动（记录 PID 便于清理）
nohup /tmp/zjdns-server -config /tmp/zjdns-bench/server.json > /tmp/zjdns-bench/server.log 2>&1 &

# 冒烟测试
dig @127.0.0.1 -p 10533 www.bench.test A +short   # 应输出 1.2.3.4
```

> **注意**：`log_level: "error"` 压测时最小化日志开销。排障时改 `"debug"`。

> **端口冲突**：启动前确认端口未被其他实例占用（`lsof -i :10533`）。测试期间
> 反复重启时，用 `pkill -f zjdns-server` 清理残留（残留实例会占用端口并干扰结果）。

## 3. 客户端构建与用法

```bash
go build -o /tmp/benchclient ./docs/benchmark/loadtest
```

```text
用法:
  -proto string      协议: udp tcp tls quic https http3 dtls tlcp http-tlcp dtlcp dnscrypt
  -addr string       服务端地址（https/http3/http-tlcp 传完整 URL）
  -servername string TLS ServerName（DNSCrypt 传 provider name）
  -public-key string DNSCrypt provider 公钥（hex）
  -workers int       并发数（默认 32）
  -seconds int       时长秒（默认 30）
  -qname string      查询名（默认 www.bench.test.，需匹配 zone 规则）
  -pprof string      客户端 pprof 地址（默认 127.0.0.1:6061）
```

各协议地址对照（对应上面的服务端配置）：

| 协议 | `-proto` | `-addr` | 备注 |
|------|----------|---------|------|
| UDP | `udp` | `127.0.0.1:10533` | |
| TCP | `tcp` | `127.0.0.1:10533` | |
| TLS | `tls` | `127.0.0.1:10853` | `-servername zjdns-test.local` |
| QUIC | `quic` | `127.0.0.1:10784` | |
| HTTPS | `https` | `https://127.0.0.1:10443/dns-query` | |
| HTTP3 | `http3` | `https://127.0.0.1:10444/dns-query` | |
| DTLS | `dtls` | `127.0.0.1:10434` | |
| TLCP | `tlcp` | `127.0.0.1:10850` | |
| HTTP-TLCP | `http-tlcp` | `https://127.0.0.1:10440/dns-query` | |
| DTLCP | `dtlcp` | `127.0.0.1:8542` | |
| DNSCrypt | `dnscrypt` | `127.0.0.1:12443` | `-servername 2.dnscrypt-cert.zjdns-test.local` `-public-key <公钥>` |
| DNSCrypt-TCP | `dnscrypt-tcp` | `127.0.0.1:12443` | 同 DNSCrypt（强制 TCP 传输） |

示例（单协议 30 秒，32 并发）：

```bash
/tmp/benchclient -proto quic -addr 127.0.0.1:10784 -workers 32 -seconds 30
# proto=quic        ok=689142  fail=1      qps=22971.4    avg=1.39    ms min=0.07    ms max=5103.06  ms
```

一轮全协议（UDP → DNSCrypt，各 15 秒）：

```bash
for proto in udp tcp tls quic https http3 dtls tlcp http-tlcp dtlcp dnscrypt dnscrypt-tcp; do
  case "$proto" in
    udp)      addr="127.0.0.1:10533" ;;
    tcp)      addr="127.0.0.1:10533" ;;
    tls)      addr="127.0.0.1:10853" ;;
    quic)     addr="127.0.0.1:10784" ;;
    https)    addr="https://127.0.0.1:10443/dns-query" ;;
    http3)    addr="https://127.0.0.1:10444/dns-query" ;;
    dtls)     addr="127.0.0.1:10434" ;;
    tlcp)     addr="127.0.0.1:10850" ;;
    http-tlcp) addr="https://127.0.0.1:10440/dns-query" ;;
    dtlcp)    addr="127.0.0.1:8542" ;;
    dnscrypt|dnscrypt-tcp) addr="127.0.0.1:12443" ;;
  esac
  pk=""; sn="zjdns-test.local"
  if [ "$proto" = "dnscrypt" ]; then
    pk="1498ACC39ABEA9A0102FA655DA6BE74084CEF4AFC9992E43FDAE364ED156DE53"
    sn="2.dnscrypt-cert.zjdns-test.local"
  fi
  /tmp/benchclient -proto "$proto" -addr "$addr" -public-key "$pk" \
    -servername "$sn" -workers 32 -seconds 15
done
```

dnsperf 对照（UDP/TCP 高并发，客户端无法开 pprof——C 程序）：

```bash
echo "www.bench.test A" > /tmp/q.txt
dnsperf -s 127.0.0.1 -p 10533 -d /tmp/q.txt -c 1000 -l 60 -Q 5000000
```

## 4. pprof 采集

服务端 pprof 在 `6060`，客户端在 `6061`（`-pprof` 可改）。

**压测期间抓 CPU profile**（`seconds` 覆盖压测窗口）：

```bash
# 先启动压测（后台），3 秒后抓 30 秒 profile
/tmp/benchclient -proto quic -addr 127.0.0.1:10784 -workers 32 -seconds 40 > /tmp/run.txt 2>&1 &
sleep 3
curl -s -o /tmp/quic-server.cpu 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'
curl -s -o /tmp/quic-client.cpu 'http://127.0.0.1:6061/debug/pprof/profile?seconds=30'
wait
```

**内存快照**（压测结束、连接回收后抓——避免把在途连接算作泄漏）：

```bash
curl -s -o /tmp/server-heap.prof 'http://127.0.0.1:6060/debug/pprof/heap'
```

**goroutine 数量**（泄漏检测：压测前 vs 压测后等 idle 回收）：

```bash
curl -s 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=1' | grep 'goroutine profile: total'
# 压测前: goroutine profile: total 140
# 压测后（等 60s 回收）: goroutine profile: total 140   ← 无泄漏
```

**block profile**（查询卡在哪——定位等待/锁竞争，客户端侧尤其有用）：

```bash
curl -s -o /tmp/client.block 'http://127.0.0.1:6061/debug/pprof/block?seconds=20'
```

## 5. 分析流程

```bash
# CPU 瓶颈（服务端）——top 看热点，或生成火焰图
go tool pprof -top -nodecount=20 /tmp/quic-server.cpu
go tool pprof -http=:8080 /tmp/quic-server.cpu        # 浏览器火焰图

# 内存（inuse_space 看真实占用，alloc_objects 看分配热点）
go tool pprof -top -inuse_space /tmp/server-heap.prof
go tool pprof -top -alloc_objects /tmp/server-heap.prof

# goroutine 泄漏（状态分布 + 滞留时长）
curl -s 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=2' > /tmp/goroutines.txt
grep -oE 'goroutine [0-9]+ \[[^]]+\]' /tmp/goroutines.txt | sort | uniq -c | sort -rn

# 阻塞（block profile）
go tool pprof -top -nodecount=10 /tmp/client.block
```

**判断要点**：

| 现象 | 含义 |
|------|------|
| `syscall.rawsyscalln` + `kevent`/`pthread_cond` 占大头 | I/O 绑定（网络轮询），非应用逻辑瓶颈 |
| 应用中间件（Zone/EDNS/Cache）占比低 | 管线本身健康 |
| block profile 大量阻塞在某库调用（如 `OpenStreamSync`） | 协议栈配额/等待问题 |
| goroutine 压测前后不回落 | 连接/协程泄漏（先等 idle 回收再下结论） |
| 某协议 QPS 比其余低一个数量级 | 该协议路径有瓶颈（参考已发现问题） |

## 6. 已发现问题（参考）

这套方法此前发现并修复的三个问题，可作排查模板：

| 问题 | 症状 | 根因 | 修复 |
|------|------|------|------|
| **DoQ 吞吐崩塌** | QUIC 78 QPS（其他协议 20-27k），block profile 73% 阻塞在 `OpenStreamSync` | 服务端 `MaxIncomingStreams=256` 秒级耗尽客户端流配额；quic-go 只在流完全关闭后发 MAX_STREAMS（受 25ms ACK 延迟拖累） | 配额 256→65535 + 客户端 `OpenStreamSync` 100ms 预算（配额耗尽快速换连接）→ 22,971 QPS |
| **TCP fallback ID mismatch** | TCP 1.5% 查询报 `dns: ID mismatch`（5812/371069） | pool 改写 msg.ID 后失败，fallback 的 miekg 复用残留 trackingID 的 msg.Data | pool `Exchange` 失败时清 `msg.Data` → 331,823 查询 0 失败 |
| **DTLCP 并发全失败** | 并发客户端握手全部超时（单连接 9.3k QPS 正常） | gotlcp 所有连接共享一个 UDP socket，同步 accept 时新客户端握手包被当前连接"偷走" | 服务端 per-client 数据报多路复用（`demuxPacketConn`），每连接独立队列 + goroutine → 25,442 QPS |
| **缓存查询 ORDER BY 开销** | `_sqlite3VdbeExec` 占 CPU 31.8%（建临时 btree），全协议 QPS 偏低 | `StmtEntryFallback` 的表达式 `ORDER BY CASE ecs_prefix` 使 SQLite 每查询建临时 btree | 去掉 ORDER BY/LIMIT，Go 侧从 ≤5 行中选最优候选 → QPS +12~24% |
| **bogus 缓存 + sticky EDE** | `dnssec_enforce` 实例命中未验证缓存绕过 enforce；正常签名域显示 EDE 6（DNSSEC Bogus）且无缓存 | (a) bogus 结果写入共享缓存后 enforce 实例直接命中 (b) 中间级验证失败的 `chain.lastEDECode` 粘滞到最终 validated 响应 | (a) `dnssecCacheable` 禁止缓存 unvalidated+bogus-EDE (b) 验证成功时清零 `lastEDECode` → 全协议基线 0 失败 |
