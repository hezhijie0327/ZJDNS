package utils

import (
	"log"
	"os"
	"time"
)

const (
	// Speedtest配置
	DefaultSpeedTestTimeout     = 1 * time.Second
	DefaultSpeedTestConcurrency = 4
	DefaultSpeedTestCacheTTL    = 900 * time.Second
	SpeedTestDebounceInterval   = 10 * time.Second
)

// Constants
const (
	DefaultCacheTTLSeconds     = 300
	HTTPClientRequestTimeout   = 5 * time.Second
	PublicIPDetectionTimeout   = 3 * time.Second
	SecureConnHandshakeTimeout = 3 * time.Second
)

// Color constants for logging
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorGray   = "\033[90m"
)

const (
	LogNone LogLevel = iota - 1
	LogError
	LogWarn
	LogInfo
	LogDebug
)

var (
	logConfig = &LogConfig{
		level:     LogInfo,
		useColor:  true,
		useEmojis: true,
	}
	customLogger = log.New(os.Stdout, "", 0)
)
