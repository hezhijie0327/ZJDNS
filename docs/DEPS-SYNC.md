# 依赖上游同步巡检

**目的**:每周对 go.mod 全部直接依赖做一次「pin vs 上游 HEAD」核查,吸收近一周改动、
发现需要适配的 API 变化和可借力的新能力。全程约 1 小时(以克隆耗时为主)。

**方法**:代理查版本只是参考,**git 仓库才是 ground truth**——逐仓库比对 pinned
commit 与上游 HEAD、拉取近一周 `git log`,按影响分类决策。

## 巡检步骤

```bash
# 1. 代理侧查最新版本(仅参考;goproxy.io 对 gitee 模块会 502,proxy.golang.org 可能不可达)
go list -m -u codeberg.org/miekg/dns github.com/quic-go/quic-go ...  # 全部直接依赖

# 2. 并行克隆 9 个直接依赖仓库(替换 <pin> 为 go.mod 里的 commit/tag)
mkdir -p /tmp/dep-review && cd /tmp/dep-review
(git clone https://codeberg.org/miekg/dns dns &)           # 或 git fetch 已有克隆
(git clone https://github.com/quic-go/quic-go &)
(git clone https://github.com/pion/dtls dtls &)            # master 即 v3
(git clone https://gitlab.com/go-extension/tls etls &)
(git clone https://gitlab.com/go-extension/http ehttp &)
(git clone https://github.com/cloudflare/circl &)
(git clone https://gitee.com/Trisia/gotlcp &)
(git clone https://github.com/emmansun/gmsm &)
(git clone https://github.com/klauspost/compress &)

# 3. 每个仓库:近一周提交 + 自 pin 以来的增量
git -C <repo> log --oneline --since="7 days ago"
git -C <repo> log --oneline <pin>..HEAD        # pseudo-version 的 12 位 hex 即 commit
git -C <repo> diff --stat <tag>..HEAD -- . ':(exclude)internal' ':(exclude).github'  # tag pin 时看公共面

# 4. 代码 diff 逐条分类(见下),grep 本仓库使用面评估影响
grep -rl "<module path>" --include="*.go" .

# 5. 验证:构建 + 全量测试 + lint
go build ./... && go test ./... -short && golangci-lint run
```

## 改动分类(四档决策)

| 分类 | 判定 | 动作 |
|------|------|------|
| **必须适配** | 公共 API 签名变化、构造函数重命名、行为破坏 | 升级 pin + 改代码,同一 commit 提交(参考 8/29–8/30 pion/dtls v3 重构适配) |
| **自动受益** | 行为修复、性能优化、合规修复,API 不变 | 仅升级 pin;确认测试全绿即可 |
| **可采纳能力** | 新功能与本项目场景契合 | 按需实现,结论与差异分析留在实现/升级 commit 里(如 `4a59f92` 的 SM3 DS) |
| **无关** | `internal/`、CI、文档、无关平台(riscv64 汇编等) | 不动;tag pin 等下个 tag 再说 |

## 直接依赖清单

| 依赖 | 仓库 | 角色 |
|------|------|------|
| codeberg.org/miekg/dns | codeberg.org/miekg/dns | DNS 消息/类型/解析(fork) |
| github.com/quic-go/quic-go | github.com/quic-go/quic-go | QUIC/DoQ/DoH3 |
| github.com/pion/dtls/v3 | github.com/pion/dtls | DTLS 1.2+ 客户端/服务端 |
| gitlab.com/go-extension/tls | gitlab.com/go-extension/tls | eTLS(crypto/tls fork + KTLS) |
| gitlab.com/go-extension/http | gitlab.com/go-extension/http | eHTTP(net/http + 原生 eTLS) |
| github.com/cloudflare/circl | github.com/cloudflare/circl | X-Wing PQ/T KEM(DNSCrypt) |
| github.com/emmansun/gmsm | github.com/emmansun/gmsm | SM2/SM3/SM4/XTS(TLCP 侧 + DNSSEC SM3 DS) |
| gitee.com/Trisia/gotlcp | gitee.com/Trisia/gotlcp | TLCP/DTLCP 协议栈 |
| github.com/klauspost/compress | github.com/klauspost/compress | zstd(DNS wire 压缩) |

golang.org/x/{crypto,net,sync,sys} 走 tag,代理 `go list -m -u` 无更新即最新。

## 注意事项

- **pin 策略**：伪版本(commit pin)保持在上游 HEAD;tag 发布型(gmsm、x/*)跟最新 tag。
- **与 CI 的关系**:`.github/workflows/deps.yml`(手动触发)对 8 个 commit-pin 依赖执行
  `go get -u <mod>@<branch>` + PR;本地巡检等价于先跑一遍该命令(`git diff go.mod` 为空即
  已全部分支 HEAD),再补 gmsm/x/* 和逐仓库 diff 阅读——CI 保证「跟上」,巡检回答「跟进了什么」。
- **clone 不下来时的替代路径**：不必整仓克隆——
  ```bash
  go doc codeberg.org/miekg/dns <Type/Func>          # 查当前 pin 版本的 API 签名
  go mod download <mod>@<ref>                        # 只拉某 ref 的源码 zip 进 module cache
  diff -r "$(go env GOMODCACHE)/<mod>@<old>" \
        "$(go env GOMODCACHE)/<mod>@<new>"           # 两个版本间的源码 diff,无 git 也能看改动
  ```
- 代理报 502 / 超时不影响结论——步骤 2 的 git 比对才是依据。
- Codeberg 克隆慢(全量约 10 分钟),可先做其余 8 个仓库;Codeberg 也有 Gitea API 可快速拉周提交:
  `https://codeberg.org/api/v1/repos/miekg/dns/commits?since=<ISO8601>&limit=50`
- 升级 pin 后如上游有 API 破坏,适配代码与 pin 升级同一 commit,便于回溯。
