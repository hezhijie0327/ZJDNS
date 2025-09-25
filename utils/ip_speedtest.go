package utils

import (
	"context"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"zjdns/types"
)

const (
	// Speedtest配置
	DefaultSpeedTestTimeout     = 1 * time.Second
	DefaultSpeedTestConcurrency = 4
	DefaultSpeedTestCacheTTL    = 900 * time.Second
	SpeedTestDebounceInterval   = 10 * time.Second
)

// SpeedTestMethod 速度测试方法
type SpeedTestMethod struct {
	// 测试类型: icmp, tcp
	Type string `json:"type"`
	// 端口号（仅对TCP有效）
	Port string `json:"port,omitempty"`
	// 超时时间（毫秒）
	Timeout int `json:"timeout"`
}

// SpeedTester 速度测试器
type SpeedTester struct {
	// 测速超时时间
	timeout time.Duration
	// 并发测速数量
	concurrency int
	// 测速结果缓存
	cache map[string]*SpeedTestResult
	// 缓存锁
	cacheMutex sync.RWMutex
	// 缓存过期时间
	cacheTTL time.Duration
	// ICMP连接
	icmpConn4 *icmp.PacketConn
	// IPv6的ICMP连接
	icmpConn6 *icmp.PacketConn
	// 测试方法配置
	methods []types.SpeedTestMethod
}

// SpeedTestResult 测速结果
type SpeedTestResult struct {
	IP        string
	Latency   time.Duration
	Reachable bool
	Timestamp time.Time
}

// NewSpeedTester 创建新的速度测试器
func NewSpeedTester(methods []types.SpeedTestMethod) *SpeedTester {
	st := &SpeedTester{
		timeout:     DefaultSpeedTestTimeout,
		concurrency: DefaultSpeedTestConcurrency,
		cache:       make(map[string]*SpeedTestResult),
		cacheTTL:    DefaultSpeedTestCacheTTL,
		methods:     methods,
	}

	// 初始化ICMP连接
	st.initICMP()

	return st
}

// initICMP 初始化ICMP连接
// initICMP 初始化ICMP连接
func (st *SpeedTester) initICMP() {
	// 创建IPv4 ICMP连接
	conn4, err := icmp.ListenPacket("ip4:icmp", "")
	if err == nil {
		st.icmpConn4 = conn4
	} else {
		// 如果是因为权限问题导致的错误，直接忽略而不是降级到UDP
		if strings.Contains(err.Error(), "operation not permitted") {
			writeLog(LogDebug, "📍 速度测试: 无权限创建IPv4 ICMP连接，跳过ICMP测试")
		} else {
			// 其他错误也直接忽略，不降级到UDP
			writeLog(LogDebug, "📍 速度测试: 无法创建IPv4 ICMP连接: %v", err)
		}
	}

	// 创建IPv6 ICMP连接（仅在支持IPv6的系统上）
	conn6, err := icmp.ListenPacket("ip6:ipv6-icmp", "")
	if err == nil {
		st.icmpConn6 = conn6
	} else {
		// 如果是因为权限问题导致的错误，直接忽略而不是降级到UDP
		if strings.Contains(err.Error(), "operation not permitted") {
			writeLog(LogDebug, "📍 速度测试: 无权限创建IPv6 ICMP连接，跳过ICMP测试")
		} else {
			// 其他错误也直接忽略，不降级到UDP
			writeLog(LogDebug, "📍 速度测试: 无法创建IPv6 ICMP连接: %v", err)
		}
	}
}

// Close 关闭ICMP连接
func (st *SpeedTester) Close() error {
	if st.icmpConn4 != nil {
		// 忽略关闭错误
		_ = st.icmpConn4.Close()
	}
	if st.icmpConn6 != nil {
		// 忽略关闭错误
		_ = st.icmpConn6.Close()
	}
	return nil
}

// PerformSpeedTestAndSort 对DNS响应中的A/AAAA记录进行测速并排序
// PerformSpeedTestAndSort 对DNS响应进行测速并排序
func (st *SpeedTester) PerformSpeedTestAndSort(response *dns.Msg) *dns.Msg {
	if response == nil {
		writeLog(LogDebug, "📍 速度测试: 响应为空")
		return response
	}

	writeLog(LogDebug, "📍 速度测试: 开始处理响应，答案记录数: %d", len(response.Answer))

	// 分离不同类型的记录
	var aRecords []*dns.A
	var aaaaRecords []*dns.AAAA
	var cnameRecords []dns.RR
	var otherRecords []dns.RR

	for _, answer := range response.Answer {
		switch record := answer.(type) {
		case *dns.A:
			aRecords = append(aRecords, record)
		case *dns.AAAA:
			aaaaRecords = append(aaaaRecords, record)
		case *dns.CNAME:
			cnameRecords = append(cnameRecords, record)
		default:
			otherRecords = append(otherRecords, record)
		}
	}

	writeLog(LogDebug, "📍 速度测试: A记录数=%d, AAAA记录数=%d, CNAME记录数=%d", len(aRecords), len(aaaaRecords), len(cnameRecords))

	// 对A记录进行测速和排序
	if len(aRecords) > 1 {
		writeLog(LogDebug, "📍 速度测试: 对%d个A记录进行测速排序", len(aRecords))
		aRecords = st.sortARecords(aRecords)
	} else {
		writeLog(LogDebug, "📍 速度测试: A记录数不足或等于1，跳过测速")
	}

	// 对AAAA记录进行测速和排序
	if len(aaaaRecords) > 1 {
		writeLog(LogDebug, "📍 速度测试: 对%d个AAAA记录进行测速排序", len(aaaaRecords))
		aaaaRecords = st.sortAAAARecords(aaaaRecords)
	} else {
		writeLog(LogDebug, "📍 速度测试: AAAA记录数不足或等于1，跳过测速")
	}

	// 重新构建响应，保持正确的DNS记录顺序
	response.Answer = []dns.RR{}

	// 先添加CNAME记录（如果有的话）
	response.Answer = append(response.Answer, cnameRecords...)

	// 再添加A记录
	for _, record := range aRecords {
		response.Answer = append(response.Answer, record)
	}

	// 再添加AAAA记录
	for _, record := range aaaaRecords {
		response.Answer = append(response.Answer, record)
	}

	// 最后添加其他记录
	response.Answer = append(response.Answer, otherRecords...)

	writeLog(LogDebug, "📍 速度测试: 处理完成，答案记录数: %d", len(response.Answer))

	return response
}

// sortARecords 对A记录按延迟排序
// sortARecords 对A记录进行排序
func (st *SpeedTester) sortARecords(records []*dns.A) []*dns.A {
	if len(records) <= 1 {
		return records
	}

	// 提取IP地址
	ips := make([]string, len(records))
	for i, record := range records {
		ips[i] = record.A.String()
	}

	// 执行测速
	results := st.speedTest(ips)

	// 根据测速结果排序
	sort.Slice(records, func(i, j int) bool {
		ipI := records[i].A.String()
		ipJ := records[j].A.String()

		resultI, okI := results[ipI]
		resultJ, okJ := results[ipJ]

		// 如果无法获取测速结果，保持原顺序
		if !okI || !okJ {
			return i < j
		}

		// 不可达的地址排在后面
		if !resultI.Reachable && resultJ.Reachable {
			return false
		}
		if resultI.Reachable && !resultJ.Reachable {
			return true
		}

		// 都不可达或都可达，按延迟排序
		return resultI.Latency < resultJ.Latency
	})

	return records
}

// sortAAAARecords 对AAAA记录按延迟排序
func (st *SpeedTester) sortAAAARecords(records []*dns.AAAA) []*dns.AAAA {
	if len(records) <= 1 {
		return records
	}

	// 提取IP地址
	ips := make([]string, len(records))
	for i, record := range records {
		ips[i] = record.AAAA.String()
	}

	// 执行测速
	results := st.speedTest(ips)

	// 根据测速结果排序
	sort.Slice(records, func(i, j int) bool {
		ipI := records[i].AAAA.String()
		ipJ := records[j].AAAA.String()

		resultI, okI := results[ipI]
		resultJ, okJ := results[ipJ]

		// 如果无法获取测速结果，保持原顺序
		if !okI || !okJ {
			return i < j
		}

		// 不可达的地址排在后面
		if !resultI.Reachable && resultJ.Reachable {
			return false
		}
		if resultI.Reachable && !resultJ.Reachable {
			return true
		}

		// 都不可达或都可达，按延迟排序
		return resultI.Latency < resultJ.Latency
	})

	return records
}

// speedTest 对IP列表进行测速
func (st *SpeedTester) speedTest(ips []string) map[string]*SpeedTestResult {
	// 检查缓存
	cachedResults := make(map[string]*SpeedTestResult)
	remainingIPs := []string{}

	st.cacheMutex.RLock()
	now := time.Now()
	for _, ip := range ips {
		if result, exists := st.cache[ip]; exists {
			// 检查缓存是否过期
			if now.Sub(result.Timestamp) < st.cacheTTL {
				cachedResults[ip] = result
			} else {
				remainingIPs = append(remainingIPs, ip)
			}
		} else {
			remainingIPs = append(remainingIPs, ip)
		}
	}
	st.cacheMutex.RUnlock()

	// 如果所有IP都有有效的缓存结果，直接返回
	if len(remainingIPs) == 0 {
		writeLog(LogDebug, "📍 速度测试: 所有IP都有有效缓存，直接返回缓存结果")
		return cachedResults
	}

	writeLog(LogDebug, "📍 速度测试: 需要测试%d个IP，%d个IP使用缓存", len(remainingIPs), len(cachedResults))

	// 对剩余IP执行测速
	newResults := st.performSpeedTest(remainingIPs)

	// 合并结果
	results := make(map[string]*SpeedTestResult)
	for ip, result := range cachedResults {
		results[ip] = result
	}
	for ip, result := range newResults {
		results[ip] = result
	}

	// 更新缓存
	st.cacheMutex.Lock()
	for ip, result := range newResults {
		st.cache[ip] = result
	}
	st.cacheMutex.Unlock()

	return results
}

// performSpeedTest 并发执行IP测速
func (st *SpeedTester) performSpeedTest(ips []string) map[string]*SpeedTestResult {
	writeLog(LogDebug, "📍 速度测试: 开始并发测速%d个IP", len(ips))

	// 创建带缓冲的通道，限制并发数
	semaphore := make(chan struct{}, st.concurrency)
	resultChan := make(chan *SpeedTestResult, len(ips))

	// 启动测速任务
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			// 获取信号量
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 执行单个IP测速
			result := st.testSingleIP(ip)
			resultChan <- result
		}(ip)
	}

	// 等待所有测速任务完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集测速结果
	results := make(map[string]*SpeedTestResult)
	for result := range resultChan {
		results[result.IP] = result
	}

	writeLog(LogDebug, "📍 速度测试: 并发测速完成，共获得%d个结果", len(results))

	return results
}

// testSingleIP 对单个IP进行测速
func (st *SpeedTester) testSingleIP(ip string) *SpeedTestResult {
	writeLog(LogDebug, "📍 速度测试: 开始测试IP %s", ip)

	result := &SpeedTestResult{
		IP:        ip,
		Timestamp: time.Now(),
	}

	// 根据配置的方法进行测速
	// 创建带超时的上下文
	totalTimeout := time.Duration(st.timeout)
	totalTimeoutCtx, totalCancel := context.WithTimeout(context.Background(), totalTimeout)
	defer totalCancel()

	// 按照配置的测试方法顺序进行测试
	for _, method := range st.methods {
		select {
		case <-totalTimeoutCtx.Done():
			// 总超时时间已到
			result.Reachable = false
			result.Latency = st.timeout
			writeLog(LogDebug, "📍 速度测试: IP %s 总超时，标记为不可达", ip)
			return result
		default:
		}

		var latency time.Duration
		switch method.Type {
		case "icmp":
			latency = st.pingWithICMP(ip, time.Duration(method.Timeout)*time.Millisecond)
		case "tcp":
			latency = st.pingWithTCP(ip, method.Port, time.Duration(method.Timeout)*time.Millisecond)
		case "udp":
			latency = st.pingWithUDP(ip, method.Port, time.Duration(method.Timeout)*time.Millisecond)
		default:
			continue
		}

		if latency >= 0 {
			result.Reachable = true
			result.Latency = latency
			writeLog(LogDebug, "📍 速度测试: IP %s %s 测试成功，延迟: %v", ip, method.Type, result.Latency)
			return result
		}
	}

	// 所有尝试都失败
	result.Reachable = false
	result.Latency = st.timeout
	writeLog(LogDebug, "📍 速度测试: IP %s 所有连接尝试失败，标记为不可达", ip)
	return result
}

// pingWithICMP 使用ICMP ping测试IP延迟
func (st *SpeedTester) pingWithICMP(ip string, timeout time.Duration) time.Duration {
	writeLog(LogDebug, "📍 速度测试: 开始ICMP ping测试 %s", ip)

	// 解析IP地址
	dst, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		writeLog(LogDebug, "📍 速度测试: 无法解析IP地址 %s: %v", ip, err)
		return -1
	}

	// 选择合适的ICMP连接
	var conn *icmp.PacketConn
	if dst.IP.To4() != nil {
		conn = st.icmpConn4
	} else {
		conn = st.icmpConn6
	}

	// 检查是否有可用的ICMP连接
	if conn == nil {
		writeLog(LogDebug, "📍 速度测试: 没有可用的ICMP连接用于测试 %s", ip)
		return -1
	}

	// 创建ICMP消息类型
	var icmpType icmp.Type
	var protocol int
	if dst.IP.To4() != nil {
		icmpType = ipv4.ICMPTypeEcho
		protocol = 1 // ICMP协议号
	} else {
		icmpType = ipv6.ICMPTypeEchoRequest
		protocol = 58 // IPv6 ICMP协议号
	}

	// 创建ICMP消息
	wm := icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("ZJDNS Speed Test"),
		},
	}

	// 序列化ICMP消息
	wb, err := wm.Marshal(nil)
	if err != nil {
		writeLog(LogDebug, "📍 速度测试: 无法序列化ICMP消息 %s: %v", ip, err)
		return -1
	}

	// 设置写入超时
	// 忽略设置超时可能的错误
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))

	// 发送ICMP消息
	start := time.Now()

	// 尝试直接写入
	_, err = conn.WriteTo(wb, dst)
	if err != nil {
		writeLog(LogDebug, "📍 速度测试: ICMP消息发送失败 %s: %v", ip, err)
		return -1
	}

	// 设置读取超时
	// 忽略设置超时可能的错误
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	// 读取回复
	rb := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(rb)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			writeLog(LogDebug, "📍 速度测试: ICMP ping超时 %s", ip)
		} else {
			writeLog(LogDebug, "📍 速度测试: 读取ICMP回复失败 %s: %v", ip, err)
		}
		return -1
	}

	writeLog(LogDebug, "📍 速度测试: 收到来自 %v 的回复，大小 %d 字节", peer, n)

	// 解析回复
	rm, err := icmp.ParseMessage(protocol, rb[:n])
	if err != nil {
		writeLog(LogDebug, "📍 速度测试: 无法解析ICMP回复 %s: %v", ip, err)
		return -1
	}

	// 检查回复类型
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
		// 成功收到回复
		latency := time.Since(start)
		writeLog(LogDebug, "📍 速度测试: ICMP ping成功 %s，延迟: %v", ip, latency)
		return latency
	default:
		writeLog(LogDebug, "📍 速度测试: 收到意外的ICMP消息类型 %s: %v", ip, rm.Type)
		return -1
	}
}

// pingWithTCP 使用TCP连接测试IP和端口的延迟
func (st *SpeedTester) pingWithTCP(ip, port string, timeout time.Duration) time.Duration {
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 记录开始时间
	start := time.Now()

	// 尝试建立TCP连接
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		writeLog(LogDebug, "📍 速度测试: TCP连接失败 %s:%s - %v", ip, port, err)
		return -1
	}

	// 记录延迟并关闭连接
	latency := time.Since(start)
	// 忽略关闭连接的错误
	_ = conn.Close()

	writeLog(LogDebug, "📍 速度测试: TCP连接成功 %s:%s，延迟: %v", ip, port, latency)

	return latency
}

// pingWithUDP 使用UDP连接测试IP和端口的延迟
func (st *SpeedTester) pingWithUDP(ip, port string, timeout time.Duration) time.Duration {
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 记录开始时间
	start := time.Now()

	// 尝试建立UDP连接
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(ip, port))
	if err != nil {
		writeLog(LogDebug, "📍 速度测试: UDP连接失败 %s:%s - %v", ip, port, err)
		return -1
	}

	// 发送一个空的UDP包
	_, writeErr := conn.Write([]byte{})
	if writeErr != nil {
		writeLog(LogDebug, "📍 速度测试: UDP发送数据失败 %s:%s - %v", ip, port, writeErr)
		// 忽略关闭连接的错误
		_ = conn.Close()
		return -1
	}

	// 记录延迟并关闭连接
	latency := time.Since(start)
	// 忽略关闭连接的错误
	_ = conn.Close()

	writeLog(LogDebug, "📍 速度测试: UDP连接成功 %s:%s，延迟: %v", ip, port, latency)

	return latency
}

// Cleanup 清理过期缓存
func (st *SpeedTester) Cleanup() {
	st.cacheMutex.Lock()
	defer st.cacheMutex.Unlock()

	now := time.Now()
	for ip, result := range st.cache {
		if now.Sub(result.Timestamp) >= st.cacheTTL {
			delete(st.cache, ip)
		}
	}
}

// ClearCache 清空缓存
func (st *SpeedTester) ClearCache() {
	st.cacheMutex.Lock()
	defer st.cacheMutex.Unlock()

	st.cache = make(map[string]*SpeedTestResult)
}
