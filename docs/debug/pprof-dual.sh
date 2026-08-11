#!/usr/bin/env bash
# 双端压测 & pprof 采集（ZJDNS ↔ ZJDNS）
#
# 与 LOADTEST.md 的区别：LOADTEST 用 benchclient 直连单端，本脚本走
# docs/debug/loopback 的完整协议链路 —— ZJDNS 转发客户端（12 种协议 +
# DNSCrypt 4 变体）→ ZJDNS 全协议服务端，两端都开 pprof。用于验证
# 协议栈 E2E 正确性、连接池复用和内存/goroutine 泄漏。
#
# 判定标准（每次审计修复后按此复核）：
#   1. 每协议 dig 冒烟 = 0 失败
#   2. 压测 ok 数 > 0 且 fail = 0
#   3. goroutine 数压测后稳定（对比同协议前后两次采样）
#   4. server 端压测全程 heap inuse 收敛（第二轮与第一轮精确一致）
#   5. 日志 0 PANIC；连接池 "dialed" 每协议 = 1、"falling back" = 0
#
# 用法: bash docs/debug/pprof-dual.sh [协议...]   # 默认全部 14 个
# 依赖: dig, curl, go tool pprof, /tmp/zjdns, /tmp/benchclient

set -u
cd "$(dirname "$0")/../.."

# ── 端口表（client 监听端口 = DEBUG.md 端口表）──
declare -A PORTS=(
  [udp]=10553 [tcp]=10653 [tls]=10753 [https]=11853 [http3]=13953
  [quic]=10953 [dtls]=14953 [tlcp]=14553 [http-tlcp]=13553 [dtlcp]=14653
  [dnscrypt]=12444 [dnscrypt-classic]=12445 [dnscrypt-ephemeral]=12446
  [dnscrypt-ephemeral-classical]=22544
)
declare -A PPROF=(
  [server]=16060
  [udp]=17061 [tcp]=17062 [tls]=17063 [https]=17064 [http3]=17065
  [quic]=17066 [dtls]=17067 [tlcp]=17068 [http-tlcp]=17069 [dtlcp]=17070
  [dnscrypt]=17071 [dnscrypt-classic]=17072 [dnscrypt-ephemeral]=17073
  [dnscrypt-ephemeral-classical]=17074
)

WORK=/tmp/zjdns-pprof
DUR=8              # 每协议压测秒数
WORKERS=8

if [ $# -gt 0 ]; then CLIENTS=("$@"); else CLIENTS=("${!PORTS[@]}"); fi

# ── 构建 ──
[ -x /tmp/zjdns ]       || go build -o /tmp/zjdns ./cmd/zjdns
[ -x /tmp/benchclient ] || go build -o /tmp/benchclient ./docs/benchmark/loadtest

# ── 生成双端配置（注入 pprof，server 附加快照持久化）──
mkdir -p "$WORK"
python3 - "$WORK" <<'PYEOF'
import json, sys
work = sys.argv[1]
srv = json.load(open('docs/debug/loopback/server.json'))
srv['server']['pprof'] = '16060'
srv['server'].setdefault('features', {})['cache'] = {
    'entries':   {'limit': {'mem': 2000, 'disk': 20000}, 'state_file': f'{work}/cache.snap'},
    'latency':   {'limit': {'mem': 1000, 'disk': 5000}, 'state_file': f'{work}/lat.snap'},
    'delegation': {'limit': {'mem': 1000, 'disk': 20000}, 'state_file': f'{work}/deleg.snap'},
}
json.dump(srv, open(f'{work}/server.json', 'w'), indent=1)
pprof = {'udp':17061,'tcp':17062,'tls':17063,'https':17064,'http3':17065,
         'quic':17066,'dtls':17067,'tlcp':17068,'http-tlcp':17069,'dtlcp':17070,
         'dnscrypt':17071,'dnscrypt-classic':17072,'dnscrypt-ephemeral':17073,
         'dnscrypt-ephemeral-classical':17074}
for name, p in pprof.items():
    cfg = json.load(open(f'docs/debug/loopback/client-{name}.json'))
    cfg['server']['pprof'] = str(p)
    json.dump(cfg, open(f'{work}/client-{name}.json', 'w'), indent=1)
PYEOF

stop_all() { pkill -f "$WORK/server.json" 2>/dev/null; pkill -f "$WORK/client-" 2>/dev/null; }
trap stop_all EXIT

# ── 启动 server ──
/tmp/zjdns -config "$WORK/server.json" > "$WORK/server.log" 2>&1 &
sleep 4
if ! dig @127.0.0.1 -p 10533 www.baidu.com A +short +time=3 +tries=1 >/dev/null 2>&1; then
  echo "FATAL: server not resolving"; exit 1
fi
echo "== server up (pprof :16060) =="

# ── 逐协议：client 冒烟 + 压测 + 双端采样 ──
for c in "${CLIENTS[@]}"; do
  port=${PORTS[$c]}
  /tmp/zjdns -config "$WORK/client-$c.json" > "$WORK/client-$c.log" 2>&1 &
  CPID=$!
  sleep 2.5

  # 冒烟
  SMOKE=$(dig @127.0.0.1 -p "$port" www.baidu.com A +short +time=3 +tries=1 2>&1 | head -1)
  # 压测
  LOAD=$(/tmp/benchclient -proto udp -addr "127.0.0.1:$port" -workers "$WORKERS" -seconds "$DUR" 2>&1 | tail -1)
  # 采样（client goroutine + heap, server heap）
  curl -s "http://127.0.0.1:${PPROF[$c]}/debug/pprof/goroutine" -o "$WORK/g-$c.prof"
  curl -s "http://127.0.0.1:${PPROF[$c]}/debug/pprof/heap"      -o "$WORK/h-$c.prof"
  curl -s "http://127.0.0.1:${PPROF[server]}/debug/pprof/heap"  -o "$WORK/hs-$c.prof"

  G=$(go tool pprof -top "$WORK/g-$c.prof" 2>/dev/null | grep "Showing nodes" | awk '{print $5}')
  kill "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null

  OK=$(echo "$LOAD" | grep -o 'ok=[0-9]*' | cut -d= -f2)
  FAIL=$(echo "$LOAD" | grep -o 'fail=[0-9]*' | cut -d= -f2)
  printf "%-28s port=%-6s smoke=%-22s ok=%-8s fail=%-4s goroutines=%s\n" \
    "$c" "$port" "${SMOKE:-TIMEOUT}" "${OK:-0}" "${FAIL:-?}" "${G:-?}"
done

# ── 汇总检查 ──
echo "== summary =="
echo -n "server heap inuse (after all load): "
go tool pprof -top -inuse_space "$WORK/hs-${CLIENTS[-1]}.prof" 2>/dev/null | grep "Showing"
echo -n "panics in server log:    "; grep -c "PANIC" "$WORK/server.log" || true
echo -n "panics in client logs:   "; grep -c "PANIC" "$WORK"/client-*.log | grep -v ':0' | wc -l
echo -n "falling back (all logs): "; grep -c "falling back" "$WORK"/*.log | grep -v ':0' | wc -l
echo "pool dialed counts (expect 1 per protocol):"
grep -h -o "TCPPOOL: dialed new connection" "$WORK"/client-*.log | wc -l
grep -h -o "UDPPOOL: dialed new socket to [^ ]*" "$WORK"/client-*.log | sort -u | wc -l
grep -h -o "UPSTREAM: dialed new QUIC connection" "$WORK"/client-*.log | wc -l
echo "profiles saved under $WORK/"
