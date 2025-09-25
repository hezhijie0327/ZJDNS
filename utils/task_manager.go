package utils

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// 优化的任务管理器
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

// NewTaskManager 创建新的任务管理器
func NewTaskManager(maxGoroutines int) *TaskManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &TaskManager{
		ctx:       ctx,
		cancel:    cancel,
		semaphore: make(chan struct{}, maxGoroutines),
	}
}

// ExecuteTask 执行任务
func (tm *TaskManager) ExecuteTask(name string, fn func(ctx context.Context) error) error {
	if tm == nil || atomic.LoadInt32(&tm.closed) != 0 {
		return nil
	}

	atomic.AddInt64(&tm.activeCount, 1)
	defer atomic.AddInt64(&tm.activeCount, -1)

	tm.wg.Add(1)
	defer tm.wg.Done()

	atomic.AddInt64(&tm.stats.executed, 1)

	defer func() { handlePanicWithContext(fmt.Sprintf("Task-%s", name)) }()
	return fn(tm.ctx)
}

// Execute is a convenience method that calls ExecuteTask with the given name and function.
// It executes the task synchronously and returns any error encountered.
// Execute 执行任务
func (tm *TaskManager) Execute(name string, fn func(ctx context.Context) error) error {
	return tm.ExecuteTask(name, fn)
}

// ExecuteAsync 异步执行任务
func (tm *TaskManager) ExecuteAsync(name string, fn func(ctx context.Context) error) {
	if tm == nil || atomic.LoadInt32(&tm.closed) != 0 {
		return
	}

	go func() {
		defer func() { handlePanicWithContext(fmt.Sprintf("AsyncTask-%s", name)) }()

		if err := tm.ExecuteTask(name, fn); err != nil {
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
