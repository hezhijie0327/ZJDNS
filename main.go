package main

import (
	"flag"
	"fmt"
	"os"
)

// ==================== 主函数 ====================

func main() {
	var configFile string
	var generateConfig bool

	flag.StringVar(&configFile, "config", "", "配置文件路径 (JSON格式)")
	flag.BoolVar(&generateConfig, "generate-config", false, "生成示例配置文件")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "🚀 ZJDNS Server\n\n")
		fmt.Fprintf(os.Stderr, "用法:\n")
		fmt.Fprintf(os.Stderr, "  %s -config <配置文件>     # 使用配置文件启动\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -generate-config       # 生成示例配置文件\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s                         # 使用默认配置启动\n\n", os.Args[0])
	}

	flag.Parse()

	if generateConfig {
		fmt.Println(GenerateExampleConfig())
		return
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		customLogger.Fatalf("💥 配置加载失败: %v", err)
	}

	server, err := NewDNSServer(config)
	if err != nil {
		customLogger.Fatalf("💥 服务器创建失败: %v", err)
	}

	writeLog(LogInfo, "🎉 ZJDNS Server 启动成功!")

	if err := server.Start(); err != nil {
		customLogger.Fatalf("💥 服务器启动失败: %v", err)
	}
}
