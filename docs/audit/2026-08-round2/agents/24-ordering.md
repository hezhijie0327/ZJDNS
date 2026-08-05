# ordering 审计

> agent: `a97e3b6bba92f5143`

发现数: 4

## ordering-01 — MEDIUM

- **位置**: `edns/edns.go:38`
- **类别**: docs
- **摘要**: RFC 6975 var 块插入在 NewHandler 的 godoc 注释与函数体之间，导出构造函数 NewHandler 丢失 godoc
- **描述**: commit 6e52ac7 新增的 var 块（dauAlgorithms/dhuAlgorithms/n3uAlgorithms，行 38-49）被插入在行 35 的注释 "// NewHandler creates a Handler with the given default ECS configuration." 与行 51 的 func NewHandler 之间。Go 的 doc comment 必须紧贴声明，因此该注释现在附加到 var 块上，导出的 NewHandler 变为无 godoc（回归：基线 93611d5 时注释紧贴 NewHandler）。decorder 要求 var 在 func 之前，var 夹在 type 与 New* 之间本身正确——问题只是注释与函数分离。
- **风险**: 公开构造函数的 godoc 丢失：go doc / 编辑器悬停显示 NewHandler 无文档，var 块却挂着误导性的 "NewHandler creates a Handler" 注释，后续维护者读到错误文档
- **修复**: 把行 35 的 "// NewHandler creates..." 注释移下到 func NewHandler（行 51）正上方，紧贴函数体；var 块保持原位（decorder 顺序正确）

## ordering-02 — LOW

- **位置**: `cache/store.go:196`
- **类别**: ordering
- **摘要**: New() 不再是 var 块之后的第一个 func——6 个新增包级辅助函数（AcquireTTLOffsets/ReleaseTTLOffsets/isZstdCompressed/scanTTLOffsets/WireHasDNSSEC/dnsSkipName，行 93-174）插入在 var 块与 New 之间
- **描述**: 基线 93611d5 中 var 块（ecsCandidatesPool，原行 66）之后紧跟 func New（原行 72）。本轮（b5f91ff/8bda354/ba1f78c）新增的 6 个包级函数被全部插入 var 块（行 90 ttloOffsetsPool 结束）与 func New（行 196）之间，违反方法论 §6.1-16「func NewFoo 应是 var 块之后的第一个 func」。其中 AcquireTTLOffsets/ReleaseTTLOffsets 与池变量配对尚可，但 isZstdCompressed/scanTTLOffsets/WireHasDNSSEC/dnsSkipName 是 wire 扫描辅助函数，与构造函数无关联。
- **风险**: SQLiteCache 的类型与其构造器之间堆叠了 6 个无关辅助函数，按类型定位构造器时需要翻越两个屏幕；后续新增函数也倾向继续插在 New 之前，使文件头持续膨胀
- **修复**: 将 New() 上移至 var 块之后第一个 func 的位置；wire 扫描辅助函数（isZstdCompressed/scanTTLOffsets/WireHasDNSSEC/dnsSkipName）移到 SQLiteCache 方法块之后（如 minTTL 附近）或拆到独立的 wire.go 文件

## ordering-03 — LOW

- **位置**: `cache/cache.go:103`
- **类别**: ordering
- **摘要**: 新增的 *Entry 方法 Unpack（行 103）与 rebuildResponseWire（行 121）插入在 var requestRecordPool 与池访问函数 AcquireRequestRecord/ReleaseRequestRecord（行 173/176）之间，把 *Entry 方法块一分为二
- **描述**: 基线中布局为 var requestRecordPool → AcquireRequestRecord → ReleaseRequestRecord → IsExpired…ShouldPrefetch（*Entry 方法连续块）。本轮新增的 Unpack/rebuildResponseWire 被插到 var 块之后、池访问函数之前，导致 *Entry 接收者的方法现在散落在两处：行 103/121 与行 182-206（IsExpired/CanServeExpired/RemainingTTL/ShouldPrefetch），中间夹着 RequestRecord 的池函数。同一接收者的方法未聚合在连续块中（方法论 §1.1 函数排序维度）。
- **风险**: *Entry 的方法聚合被打断，读者难以一次看到该类型的完整方法集；后续新增 *Entry 方法时可能再次插入错误位置，文件结构继续劣化
- **修复**: 将 Unpack/rebuildResponseWire 移到 IsExpired（行 182）之前加入 *Entry 方法块，保持 var requestRecordPool → AcquireRequestRecord/ReleaseRequestRecord 的配对相邻

## ordering-04 — LOW

- **位置**: `server/defense/poisonguard.go:152`
- **类别**: ordering
- **摘要**: 新增包级函数 delegationOrProof 插入在 *Detector 方法 classify（行 129）与 classifyRoot（行 160）之间，打断同一接收者的方法连续块
- **描述**: commit 8e51759（poisonguard 委派证明豁免）新增的包级函数 delegationOrProof 被插入在 *Detector 的方法块中间：classify(129) → delegationOrProof(152, 包级) → classifyRoot(160) → classifyTLD(185)。*Detector 的方法 Validate(75)/IsPoisonedByTLD(102)/classify(129)/classifyRoot(160)/classifyTLD(185)/isRootServerDomain(201)/isTLD(205) 因此不再连续。虽然插入点靠近首个调用点，但按方法论应放在 *Detector 方法块之后（如 isTLD 之后）。
- **风险**: *Detector 方法块被无关接收者的包级函数打断，方法聚合度下降；与 cache 包同类的散乱插入模式会蔓延
- **修复**: 将 delegationOrProof 移到 isTLD（行 205）之后、文件末尾的包级辅助区，恢复 *Detector 方法块连续

