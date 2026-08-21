# ZJDNS 文档索引

本目录是项目的全部文档与测试资产。**阅读顺序**：先 [ARCHITECTURE](ARCHITECTURE.md) 了解系统，
再按需进入下表对应文档。

## 导航

| 文档/目录 | 职责 | 何时看 |
|-----------|------|--------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 架构参考：存储设计、中间件链、连接池（4 池 × 三层上限）、防御机制、类型参考、协议实现 | 理解系统设计 |
| [FLOWCHARTS.md](FLOWCHARTS.md) | 核心功能/协议 mermaid 流程图 | 理解数据流与调用链 |
| [AUDIT-METHODOLOGY.md](AUDIT-METHODOLOGY.md) | 审计框架：18 维度、并行 agent 编排、Sprint 修复流程、质量门禁、提交规范 | 做审计前必读 |
| [audit/](audit/) | 每轮审计的详细报告与修复计划（命名 `YYYY-MM-主题/`，结构见方法论 §7） | 查历史审计结论 |
| [debug/DEBUG.md](debug/DEBUG.md) | 测试配置与 E2E 指南：loopback 全协议、防御场景、DNSSEC、外部工具对接 | 跑任何手动测试前 |
| [debug/pprof-dual.sh](debug/pprof-dual.sh) | 双端压测 & pprof 采集脚本（ZJDNS 客户端 ↔ 服务端全链路） | 审计修复后的泄漏复核 |
| [benchmark/BENCHMARK.md](benchmark/BENCHMARK.md) | Go benchmark + 外部工具（dnsperf/DNSCrypt-proxy）E2E 指南 | 性能回归检测 |
| [benchmark/LOADTEST.md](benchmark/LOADTEST.md) | benchclient 直连单端全协议压测 + pprof 分析 | 协议栈出口压测 |
| [benchmark/benchmark-baseline.txt](benchmark/benchmark-baseline.txt) | `go test -bench` 单元/集成基线（带 `-benchmem`） | 刷新/对比基准 |
| [benchmark/loadtest-baseline.txt](benchmark/loadtest-baseline.txt) | benchclient 全协议 QPS/延迟基线（12 协议） | 刷新/对比基准 |
| [benchmark/loadtest/](benchmark/loadtest/) | benchclient 压测工具源码（复用生产 `upstream.Client`） | 压测 |
| [poc/](poc/README.md) | 防御机制概念验证程序（hopguard/spoofguard/splitguard/poisonguard/capsguard） | 演示/教学 |
| [rfc/](rfc/GUIDELINE.md) | 镜像的 RFC/draft 存档 + 精华指南 | 查协议规范 |

## 压测文档边界（三份文档不重叠）

| 文档 | 场景 | 工具 | 验证对象 |
|------|------|------|----------|
| BENCHMARK.md | Go 单元/集成 benchmark + 外部客户端 E2E | `go test -bench`、dnsperf、dnscrypt-proxy | 单函数/单协议栈 |
| LOADTEST.md | benchclient 直连单端，全协议出口压测 | benchclient + pprof 双端 | `upstream.Client` 出口 + 服务端管线 |
| DEBUG.md「双端压测」 | ZJDNS 转发客户端 → ZJDNS 服务端全链路 | `pprof-dual.sh` + benchclient | 协议 E2E、连接池复用、泄漏 |

> 审计修复后的标准复核流程：跑 `pprof-dual.sh`（判定标准见 DEBUG.md「双端压测」章节），
> 刷新两条基线（命令见 CLAUDE.md），对比无回归。

## 约定

- **新增 RFC**：先 `cp rfc{number}.txt docs/rfc/` 再实现（见 rfc/GUIDELINE.md）
- **审计报告**：存 `audit/YYYY-MM-<主题>/`，命名规范见 AUDIT-METHODOLOGY.md §7
- **基线更新**：benchmark 与 loadtest 两条基线在每次性能相关改动后刷新
- **POC**：防御机制原型与 `server/defense/` 实现对应，改动实现时同步检查
