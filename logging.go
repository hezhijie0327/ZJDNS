package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// ==================== 增强日志系统 ====================

type LogLevel int

const (
	LogNone LogLevel = iota - 1
	LogError
	LogWarn
	LogInfo
	LogDebug
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorGreen  = "\033[32m"
	ColorBlue   = "\033[34m"
	ColorGray   = "\033[37m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
)

type LogConfig struct {
	level     LogLevel
	useColor  bool
	useEmojis bool
	mu        sync.RWMutex
}

var (
	logConfig = &LogConfig{
		level:     LogInfo,
		useColor:  true,
		useEmojis: true,
	}
	customLogger = log.New(os.Stdout, "", 0)
)

func (l LogLevel) String() string {
	configs := []struct {
		name  string
		emoji string
		color string
	}{
		{"NONE", "🔇", ColorGray},
		{"ERROR", "💥", ColorRed},
		{"WARN", "⚠️", ColorYellow},
		{"INFO", "✨", ColorGreen},
		{"DEBUG", "🔍", ColorBlue},
	}

	index := int(l) + 1
	if index >= 0 && index < len(configs) {
		config := configs[index]
		result := config.name

		logConfig.mu.RLock()
		useEmojis := logConfig.useEmojis
		useColor := logConfig.useColor
		logConfig.mu.RUnlock()

		if useEmojis {
			result = config.emoji + " " + result
		}

		if useColor {
			result = config.color + result + ColorReset
		}

		return result
	}
	return "UNKNOWN"
}

// 增强的日志函数，支持更多场景emoji
func writeLog(level LogLevel, format string, args ...interface{}) {
	logConfig.mu.RLock()
	currentLevel := logConfig.level
	useColor := logConfig.useColor
	logConfig.mu.RUnlock()

	if level <= currentLevel {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		message := fmt.Sprintf(format, args...)

		// 添加上下文emoji
		message = enhanceLogMessage(message)

		logLine := fmt.Sprintf("%s[%s] %s %s", ColorGray, timestamp, level.String(), message)
		if useColor {
			logLine += ColorReset
		}
		customLogger.Println(logLine)
	}
}

// 根据消息内容添加相应的emoji
func enhanceLogMessage(message string) string {
	lowerMsg := strings.ToLower(message)

	// 协议相关emoji
	if strings.Contains(lowerMsg, "tcp") && !strings.Contains(message, "🔌") {
		message = "🔌 " + message
	} else if strings.Contains(lowerMsg, "udp") && !strings.Contains(message, "📡") {
		message = "📡 " + message
	} else if strings.Contains(lowerMsg, "tls") && !strings.Contains(message, "🔐") {
		message = "🔐 " + message
	} else if strings.Contains(lowerMsg, "quic") && !strings.Contains(message, "🚀") {
		message = "🚀 " + message
	} else if strings.Contains(lowerMsg, "http3") && !strings.Contains(message, "⚡") {
		message = "⚡ " + message
	} else if strings.Contains(lowerMsg, "https") && !strings.Contains(message, "🌐") {
		message = "🌐 " + message
	}

	// 操作相关emoji
	if strings.Contains(lowerMsg, "cache") && strings.Contains(lowerMsg, "hit") && !strings.Contains(message, "🎯") {
		message = "🎯 " + message
	} else if strings.Contains(lowerMsg, "cache") && strings.Contains(lowerMsg, "miss") && !strings.Contains(message, "❌") {
		message = "❌ " + message
	} else if strings.Contains(lowerMsg, "dns") && strings.Contains(lowerMsg, "hijack") && !strings.Contains(message, "🛡️") {
		message = "🛡️ " + message
	} else if strings.Contains(lowerMsg, "memory") && strings.Contains(lowerMsg, "leak") && !strings.Contains(message, "🚰") {
		message = "🚰 " + message
	} else if strings.Contains(lowerMsg, "goroutine") && strings.Contains(lowerMsg, "leak") && !strings.Contains(message, "🕳️") {
		message = "🕳️ " + message
	} else if strings.Contains(lowerMsg, "connection") && strings.Contains(lowerMsg, "pool") && !strings.Contains(message, "🏊") {
		message = "🏊 " + message
	} else if strings.Contains(lowerMsg, "timeout") && !strings.Contains(message, "⏰") {
		message = "⏰ " + message
	} else if strings.Contains(lowerMsg, "retry") && !strings.Contains(message, "🔄") {
		message = "🔄 " + message
	} else if strings.Contains(lowerMsg, "fallback") && !strings.Contains(message, "🔙") {
		message = "🔙 " + message
	}

	return message
}

// SetLogLevel 设置日志级别
func SetLogLevel(level LogLevel) {
	logConfig.mu.Lock()
	defer logConfig.mu.Unlock()
	logConfig.level = level
}

// GetLogLevel 获取当前日志级别
func GetLogLevel() LogLevel {
	logConfig.mu.RLock()
	defer logConfig.mu.RUnlock()
	return logConfig.level
}
