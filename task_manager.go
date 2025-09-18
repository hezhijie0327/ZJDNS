package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ==================== 优化的资源管理器 ====================

type ResourceManager struct {
	dnsMessages    sync.Pool
	buffers        sync.Pool
	stringBuilders sync.Pool
	stats          struct {
		gets int64
		puts int64
		news int64
	}
}

func NewResourceManager() *ResourceManager {
	rm := &ResourceManager{}

	rm.dnsMessages = sync.Pool{
		New: func() interface{} {
			atomic.AddInt64(&rm.stats.news, 1)
			msg := &dns.Msg{}
			// 确保所有切片字段都初始化
			msg.Question = make([]dns.Question, 0)
			msg.Answer = make([]dns.RR, 0)
			msg.Ns = make([]dns.RR, 0)
			msg.Extra = make([]dns.RR, 0)
			return msg
		},
	}

	rm.buffers = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 1024)
		},
	}

	rm.stringBuilders = sync.Pool{
		New: func() interface{} {
			return &strings.Builder{}
		},
	}

	return rm
}

func (rm *ResourceManager) GetDNSMessage() *dns.Msg {
	if rm == nil {
		msg := &dns.Msg{}
		// 移除safeDNSMsgProcess补丁函数，直接初始化字段
		msg.Question = make([]dns.Question, 0)
		msg.Answer = make([]dns.RR, 0)
		msg.Ns = make([]dns.RR, 0)
		msg.Extra = make([]dns.RR, 0)
		return msg
	}

	atomic.AddInt64(&rm.stats.gets, 1)
	obj := rm.dnsMessages.Get()
	msg, ok := obj.(*dns.Msg)
	if !ok {
		msg = &dns.Msg{}
		// 移除safeDNSMsgProcess补丁函数，直接初始化字段
		msg.Question = make([]dns.Question, 0)
		msg.Answer = make([]dns.RR, 0)
		msg.Ns = make([]dns.RR, 0)
		msg.Extra = make([]dns.RR, 0)
	}

	rm.resetDNSMessageSafe(msg)
	return msg
}

func (rm *ResourceManager) resetDNSMessageSafe(msg *dns.Msg) {
	if msg == nil {
		return
	}

	// 安全重置，保留切片容量，确保不为nil
	*msg = dns.Msg{
		Question: msg.Question[:0],
		Answer:   msg.Answer[:0],
		Ns:       msg.Ns[:0],
		Extra:    msg.Extra[:0], // 确保为空切片而不是nil
	}

	// 如果任何字段为nil，重新初始化
	if msg.Question == nil {
		msg.Question = make([]dns.Question, 0)
	}
	if msg.Answer == nil {
		msg.Answer = make([]dns.RR, 0)
	}
	if msg.Ns == nil {
		msg.Ns = make([]dns.RR, 0)
	}
	if msg.Extra == nil {
		msg.Extra = make([]dns.RR, 0)
	}
}

func (rm *ResourceManager) PutDNSMessage(msg *dns.Msg) {
	if rm == nil || msg == nil {
		return
	}

	atomic.AddInt64(&rm.stats.puts, 1)
	rm.resetDNSMessageSafe(msg)
	rm.dnsMessages.Put(msg)
}

func (rm *ResourceManager) GetBuffer() []byte {
	if rm == nil {
		return make([]byte, 0, 1024)
	}
	return rm.buffers.Get().([]byte)[:0]
}

func (rm *ResourceManager) PutBuffer(buf []byte) {
	if rm == nil || buf == nil {
		return
	}
	if cap(buf) <= 8192 { // 避免保留过大的buffer
		rm.buffers.Put(buf)
	}
}

func (rm *ResourceManager) GetStringBuilder() *strings.Builder {
	if rm == nil {
		return &strings.Builder{}
	}
	sb := rm.stringBuilders.Get().(*strings.Builder)
	sb.Reset()
	return sb
}

func (rm *ResourceManager) PutStringBuilder(sb *strings.Builder) {
	if rm == nil || sb == nil {
		return
	}
	if sb.Cap() <= 4096 { // 避免保留过大的builder
		rm.stringBuilders.Put(sb)
	}
}

var globalResourceManager = NewResourceManager()

// ==================== 优化的任务管理器 ====================

type TaskManager struct {
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	semaphore   chan struct{}
	activeCount int64
	closed      int32
	stats       struct {
		executed int64
		failed   int64
		timeout  int64
	}
}

func NewTaskManager(maxGoroutines int) *TaskManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &TaskManager{
		ctx:       ctx,
		cancel:    cancel,
		semaphore: make(chan struct{}, maxGoroutines),
	}
}

func (tm *TaskManager) Execute(name string, fn func(ctx context.Context) error) error {
	if tm == nil || atomic.LoadInt32(&tm.closed) != 0 {
		return errors.New("🔒 任务管理器已关闭")
	}

	select {
	case <-tm.ctx.Done():
		return tm.ctx.Err()
	case tm.semaphore <- struct{}{}:
		defer func() { <-tm.semaphore }()
	}

	atomic.AddInt64(&tm.activeCount, 1)
	defer atomic.AddInt64(&tm.activeCount, -1)

	tm.wg.Add(1)
	defer tm.wg.Done()

	atomic.AddInt64(&tm.stats.executed, 1)

	return executeWithRecovery(fmt.Sprintf("Task-%s", name), func() error {
		return fn(tm.ctx)
	}, nil)
}

func (tm *TaskManager) ExecuteAsync(name string, fn func(ctx context.Context) error) {
	if tm == nil || atomic.LoadInt32(&tm.closed) != 0 {
		return
	}

	go func() {
		defer handlePanicWithContext(fmt.Sprintf("AsyncTask-%s", name), nil)

		if err := tm.Execute(name, fn); err != nil {
			if err != context.Canceled {
				atomic.AddInt64(&tm.stats.failed, 1)
				writeLog(LogError, "💥 异步任务执行失败 [%s]: %v", name, err)
			}
		}
	}()
}

func (tm *TaskManager) GetStats() (executed, failed, timeout int64) {
	return atomic.LoadInt64(&tm.stats.executed),
		atomic.LoadInt64(&tm.stats.failed),
		atomic.LoadInt64(&tm.stats.timeout)
}

func (tm *TaskManager) Shutdown(timeout time.Duration) error {
	if tm == nil || !atomic.CompareAndSwapInt32(&tm.closed, 0, 1) {
		return nil
	}

	writeLog(LogInfo, "🛑 正在关闭任务管理器...")
	tm.cancel()

	done := make(chan struct{})
	go func() {
		tm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		writeLog(LogInfo, "✅ 任务管理器已安全关闭")
		return nil
	case <-time.After(timeout):
		writeLog(LogWarn, "⏰ 任务管理器关闭超时")
		return fmt.Errorf("🕐 shutdown timeout")
	}
}
