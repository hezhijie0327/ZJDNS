# ZJDNS Server

🚀 高性能DNS递归解析服务器，专为现代网络环境设计

[![Go Version](https://img.shields.io/badge/Go-1.19+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()

## ✨ 特性

### 🔥 核心功能
- **高性能递归解析** - 支持并发查询，优化响应时间
- **智能缓存系统** - 内存缓存 + 持久化存储，支持LRU淘汰策略
- **DNSSEC验证** - 完整的DNS安全扩展支持
- **ECS支持** - EDNS Client Subnet，提供地理位置感知的DNS解析
- **Serve-Expired** - 过期缓存服务，提高可用性和用户体验

### 🌐 网络优化
- **连接池管理** - 复用DNS连接，减少连接开销
- **IPv6支持** - 双栈解析，支持现代网络协议
- **并发控制** - 可配置的最大并发查询数
- **根服务器冗余** - 多个根DNS服务器确保高可用性

### 📊 监控与运维
- **实时统计** - 查询次数、缓存命中率、平均响应时间
- **结构化日志** - 彩色输出、emoji标识、多级别日志
- **优雅关闭** - 信号处理，安全保存缓存数据
- **性能监控** - 内置性能指标和健康检查

## 🚀 快速开始

### 安装要求

- Go 1.19 或更高版本
- Linux/macOS/Windows 系统

### 编译安装

```bash
# 克隆项目
git clone https://github.com/yourusername/ZJDNSServer.git
cd ZJDNSServer

# 安装依赖
go mod tidy

# 编译
go build -o zjdns main.go

# 或者直接运行
go run main.go
```

### Docker 部署

```bash
# 构建镜像
docker build -t ZJDNSServer .

# 运行容器
docker run -d \
  --name zjdns \
  -p 53:53/udp \
  -p 53:53/tcp \
  -v ./cache:/app/cache \
  ZJDNSServer
```

## 📖 使用方法

### 基本使用

```bash
# 默认配置启动
./zjdns

# 指定端口和缓存大小
./zjdns -port 5353 -cache-size 50000

# 启用详细日志
./zjdns -log-level debug

# 完整配置示例
./zjdns \
  -port 53 \
  -cache-size 10000 \
  -cache-file dns_cache.gob.gz \
  -log-level info \
  -enable-stats \
  -serve-expired \
  -max-concurrency 20
```

### 系统服务配置

#### Systemd (Linux)

创建服务文件 `/etc/systemd/system/zjdns.service`：

```ini
[Unit]
Description=ZJDNS High Performance DNS Server
After=network.target

[Service]
Type=simple
User=zjdns
Group=zjdns
ExecStart=/usr/local/bin/zjdns -port 53 -log-level info
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable zjdns
sudo systemctl start zjdns
```

## ⚙️ 配置参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-port` | `53` | DNS服务器监听端口 |
| `-cache-size` | `10000` | DNS缓存条目数量限制 |
| `-cache-file` | `dns_cache.gob.gz` | 缓存持久化文件路径 |
| `-default-ecs` | `""` | 默认ECS子网地址 (如: `192.168.1.0/24`) |
| `-save-interval` | `600` | 缓存保存间隔（秒） |
| `-serve-expired` | `true` | 启用过期缓存服务 |
| `-expired-ttl` | `30` | 过期缓存响应的TTL（秒） |
| `-stale-max-age` | `86400` | 过期缓存最大保留时间（秒） |
| `-log-level` | `error` | 日志级别 (`error`/`warn`/`info`/`debug`) |
| `-enable-ipv6` | `false` | 启用IPv6根服务器支持 |
| `-max-concurrency` | `10` | 最大并发查询数 |
| `-conn-pool-size` | `20` | 连接池大小 |
| `-enable-stats` | `true` | 启用统计信息 |
| `-stats-interval` | `300` | 统计信息输出间隔（秒） |

## 🎯 性能优化

### 缓存优化

```bash
# 大内存环境，增加缓存大小
./zjdns -cache-size 100000 -save-interval 300

# 启用Serve-Expired，提高缓存利用率
./zjdns -serve-expired -expired-ttl 60 -stale-max-age 604800
```

### 并发优化

```bash
# 高负载环境
./zjdns -max-concurrency 50 -conn-pool-size 100
```

### IPv6优化

```bash
# 双栈环境
./zjdns -enable-ipv6 -default-ecs "2001:db8::/32"
```

## 📊 监控和日志

### 统计信息

服务器会定期输出统计信息：

```
[2024-01-01 12:00:00] 📋 INFO 📊 查询: 1524, 缓存命中率: 85.2%, 错误: 3, 平均耗时: 45ms
[2024-01-01 12:00:00] 📋 INFO 💾 缓存状态: 大小=8567, 命中率=85.2%, 淘汰=124, 刷新=67
```

### 日志级别

- **ERROR** 🔥 - 严重错误，影响服务运行
- **WARN** ⚠️ - 警告信息，需要关注
- **INFO** 📋 - 一般信息，服务状态
- **DEBUG** 🔍 - 详细调试信息

### 日志示例

```
[2024-01-01 12:00:00] 📋 INFO 🚀 启动高性能DNS服务器...
[2024-01-01 12:00:00] 📋 INFO 🌐 监听端口: 53
[2024-01-01 12:00:00] 📋 INFO 💾 缓存大小: 10000条
[2024-01-01 12:00:01] 🔍 DEBUG 🔍 递归解析: A example.com
[2024-01-01 12:00:01] 🔍 DEBUG ✅ 找到答案: 1条记录
[2024-01-01 12:00:01] 🔍 DEBUG 💾 缓存记录: example.com:1:1 (TTL: 300s, 答案: 1条)
```

## 🔧 故障排除

### 常见问题

#### 1. 端口占用错误

```bash
# 检查端口占用
sudo netstat -tulpn | grep :53

# 使用其他端口
./zjdns -port 5353
```

#### 2. 权限不足

```bash
# 非root用户使用高端口
./zjdns -port 1053

# 或授权能力
sudo setcap CAP_NET_BIND_SERVICE=+eip ./zjdns
```

#### 3. 缓存文件权限

```bash
# 检查缓存文件权限
ls -la dns_cache.gob.gz

# 修正权限
chmod 644 dns_cache.gob.gz
```

#### 4. DNS解析失败

```bash
# 启用调试日志
./zjdns -log-level debug

# 检查网络连接
dig @8.8.8.8 example.com
```

### 性能调优

#### 内存使用优化

```bash
# 监控内存使用
top -p $(pgrep zjdns)

# 调整缓存大小
./zjdns -cache-size 50000  # 根据可用内存调整
```

#### 网络优化

```bash
# 增加文件描述符限制
ulimit -n 65536

# 调整连接池大小
./zjdns -conn-pool-size 50
```

## 🧪 测试

### 功能测试

```bash
# 基本DNS查询测试
dig @localhost example.com

# DNSSEC测试
dig @localhost +dnssec example.com

# IPv6测试（如果启用）
dig @localhost AAAA example.com
```

### 性能测试

```bash
# 使用dnsperf进行压力测试
echo "example.com A" > queries.txt
dnsperf -s localhost -d queries.txt -c 10 -T 10

# 并发测试
for i in {1..100}; do
  dig @localhost test$i.example.com &
done
wait
```

### 缓存测试

```bash
# 第一次查询（未缓存）
time dig @localhost example.com

# 第二次查询（已缓存）
time dig @localhost example.com
```

## 🛡️ 安全建议

### 防火墙配置

```bash
# UFW配置
sudo ufw allow 53/tcp
sudo ufw allow 53/udp

# iptables配置
sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
```

### 访问控制

考虑在前端部署防火墙或反向代理，限制访问来源：

```bash
# 仅允许内网访问
sudo iptables -A INPUT -p udp --dport 53 -s 192.168.0.0/16 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 53 -j DROP
```

## 📈 生产环境部署

### 高可用配置

1. **负载均衡**: 使用HAProxy或Nginx进行负载均衡
2. **多实例部署**: 运行多个ZJDNS实例
3. **监控告警**: 集成Prometheus和Grafana

### 容器化部署

#### Dockerfile

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && go build -o zjdns main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/zjdns .
EXPOSE 53/udp 53/tcp
CMD ["./zjdns"]
```

#### Docker Compose

```yaml
version: '3.8'
services:
  zjdns:
    build: .
    ports:
      - "53:53/udp"
      - "53:53/tcp"
    volumes:
      - ./cache:/app/cache
    environment:
      - LOG_LEVEL=info
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "dig", "@localhost", "health.check"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## 🤝 贡献指南

我们欢迎所有形式的贡献！

### 开发环境设置

```bash
git clone https://github.com/yourusername/ZJDNSServer.git
cd ZJDNSServer
go mod tidy
```

### 提交规范

- 使用清晰的提交信息
- 遵循Go代码规范
- 添加适当的测试
- 更新相关文档

### 问题报告

请使用GitHub Issues报告问题，包含：

- 详细的问题描述
- 复现步骤
- 环境信息
- 相关日志

## 📄 许可证

本项目基于 MIT 许可证开源。详见 [LICENSE](LICENSE) 文件。

## 🙏 致谢

- [miekg/dns](https://github.com/miekg/dns) - 优秀的Go DNS库
- Go社区 - 提供强大的语言支持
- 所有贡献者 - 让项目更加完善

## 📞 支持

- 📧 Email: support@example.com
- 💬 Issues: [GitHub Issues](https://github.com/yourusername/ZJDNSServer/issues)
- 📚 文档: [Wiki](https://github.com/yourusername/ZJDNSServer/wiki)

---

⭐ 如果这个项目对您有帮助，请给我们一个Star！
