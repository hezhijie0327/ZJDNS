package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func NewEDNSManager(defaultSubnet string, paddingEnabled bool) (*EDNSManager, error) {
	manager := &EDNSManager{
		detector:       NewIPDetector(),
		paddingEnabled: paddingEnabled,
	}

	if defaultSubnet != "" {
		ecs, err := manager.parseECSConfig(defaultSubnet)
		if err != nil {
			return nil, fmt.Errorf("🌍 ECS配置解析失败: %w", err)
		}
		manager.defaultECS = ecs
		if ecs != nil {
			writeLog(LogInfo, "🌍 默认ECS配置: %s/%d", ecs.Address, ecs.SourcePrefix)
		}
	}

	if paddingEnabled {
		writeLog(LogInfo, "📦 DNS Padding已启用 (块大小: %d字节)", DNSPaddingBlockSizeBytes)
	}

	return manager, nil
}

func (em *EDNSManager) GetDefaultECS() *ECSOption {
	if em == nil {
		return nil
	}
	return em.defaultECS
}

func (em *EDNSManager) IsPaddingEnabled() bool {
	return em != nil && em.paddingEnabled
}

func (em *EDNSManager) calculatePaddingSize(currentSize int) int {
	// 检查是否启用padding，以及当前大小是否有效
	if !em.paddingEnabled || currentSize <= 0 {
		return 0
	}

	// 如果已经大于等于目标大小，则不添加padding
	if currentSize >= DNSPaddingMaxSizeBytes {
		return 0
	}

	// 根据规范，应该将安全连接的DNS响应填充到固定468字节
	// 计算需要添加的padding大小
	paddingSize := DNSPaddingMaxSizeBytes - currentSize

	// 确保padding大小不为负数
	if paddingSize <= 0 {
		return 0
	}

	return paddingSize
}

func (em *EDNSManager) ParseFromDNS(msg *dns.Msg) *ECSOption {
	if em == nil || msg == nil {
		return nil
	}

	// 确保msg.Extra字段安全，防止IsEdns0()出现index out of range错误
	if msg.Extra == nil {
		return nil
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}

	for _, option := range opt.Option {
		if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
			return &ECSOption{
				Family:       subnet.Family,
				SourcePrefix: subnet.SourceNetmask,
				ScopePrefix:  subnet.SourceScope,
				Address:      subnet.Address,
			}
		}
	}

	return nil
}

func (em *EDNSManager) AddToMessage(msg *dns.Msg, ecs *ECSOption, dnssecEnabled bool, isSecureConnection bool) {
	if em == nil || msg == nil {
		return
	}

	// 确保消息结构安全，防止在ExchangeContext中调用IsEdns0时出现panic
	if msg.Question == nil {
		msg.Question = []dns.Question{}
	}
	if msg.Answer == nil {
		msg.Answer = []dns.RR{}
	}
	if msg.Ns == nil {
		msg.Ns = []dns.RR{}
	}
	if msg.Extra == nil {
		msg.Extra = []dns.RR{}
	}

	// 清理现有OPT记录
	cleanExtra := make([]dns.RR, 0, len(msg.Extra))
	for _, rr := range msg.Extra {
		if rr != nil && rr.Header().Rrtype != dns.TypeOPT {
			cleanExtra = append(cleanExtra, rr)
		}
	}
	msg.Extra = cleanExtra

	// 创建新的OPT记录
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  ClientUDPBufferSizeBytes,
			Ttl:    0,
		},
	}

	if dnssecEnabled {
		opt.SetDo(true)
	}

	var options []dns.EDNS0

	// 添加ECS选项
	if ecs != nil {
		ecsOption := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        ecs.Family,
			SourceNetmask: ecs.SourcePrefix,
			SourceScope:   DefaultECSClientScope,
			Address:       ecs.Address,
		}
		options = append(options, ecsOption)
		writeLog(LogDebug, "🌍 添加ECS选项: %s/%d", ecs.Address, ecs.SourcePrefix)
	}

	// 添加Padding选项（仅对安全连接）
	if em.paddingEnabled && isSecureConnection {
		// 先添加所有其他选项（如ECS等）
		opt.Option = options
		tempMsg := *msg
		tempMsg.Extra = append(tempMsg.Extra, opt)

		// 计算当前消息大小
		currentSize := tempMsg.Len()

		// 计算需要的padding大小
		paddingSize := em.calculatePaddingSize(currentSize)

		// 添加padding选项
		if paddingSize > 0 {
			// 创建初始padding选项
			paddingOption := &dns.EDNS0_PADDING{
				Padding: make([]byte, paddingSize),
			}

			// 创建包含padding选项的完整OPT记录来计算实际大小
			tempOptWithPadding := &dns.OPT{
				Hdr: dns.RR_Header{
					Name:   ".",
					Rrtype: dns.TypeOPT,
					Class:  ClientUDPBufferSizeBytes,
					Ttl:    0,
				},
				Option: append(options, paddingOption),
			}

			// 计算包含padding的完整消息大小
			tempMsgWithPadding := *msg
			tempMsgWithPadding.Extra = append(tempMsgWithPadding.Extra, tempOptWithPadding)
			finalSize := tempMsgWithPadding.Len()

			// 精确调整padding大小以确保最终消息大小正好是468字节
			if finalSize != DNSPaddingMaxSizeBytes {
				// 计算大小差异
				diff := DNSPaddingMaxSizeBytes - finalSize

				// 调整padding大小
				newPaddingSize := paddingSize + diff

				// 确保padding大小非负
				if newPaddingSize >= 0 {
					paddingOption.Padding = make([]byte, newPaddingSize)
					options = append(options, paddingOption)
					writeLog(LogDebug, "📦 DNS Padding: %d -> %d 字节 (+%d)",
						currentSize, DNSPaddingMaxSizeBytes, newPaddingSize)
				}
			} else {
				options = append(options, paddingOption)
				writeLog(LogDebug, "📦 DNS Padding: %d -> %d 字节 (+%d)",
					currentSize, finalSize, paddingSize)
			}
		}
	}

	opt.Option = options
	msg.Extra = append(msg.Extra, opt)
}

func (em *EDNSManager) parseECSConfig(subnet string) (*ECSOption, error) {
	switch strings.ToLower(subnet) {
	case "auto":
		return em.detectPublicIP(false, true)
	case "auto_v4":
		return em.detectPublicIP(false, false)
	case "auto_v6":
		return em.detectPublicIP(true, false)
	default:
		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, fmt.Errorf("🔍 解析CIDR失败: %w", err)
		}

		prefix, _ := ipNet.Mask.Size()
		family := uint16(1)
		if ipNet.IP.To4() == nil {
			family = 2
		}

		return &ECSOption{
			Family:       family,
			SourcePrefix: uint8(prefix),
			ScopePrefix:  DefaultECSClientScope,
			Address:      ipNet.IP,
		}, nil
	}
}

// detectPublicIP 使用外部导入函数获取公网 IP 并构建 ECSOption
func (em *EDNSManager) detectPublicIP(forceIPv6, allowFallback bool) (*ECSOption, error) {
	cacheKey := fmt.Sprintf("ip_detection_%v_%v", forceIPv6, allowFallback)

	if cached, ok := em.cache.Load(cacheKey); ok {
		if cachedECS, ok := cached.(*ECSOption); ok {
			return cachedECS, nil
		}
	}

	var ecs *ECSOption
	if ip := em.detector.DetectPublicIP(forceIPv6); ip != nil {
		family := uint16(1)
		prefix := uint8(DefaultECSIPv4PrefixLen)

		if forceIPv6 {
			family = 2
			prefix = DefaultECSIPv6PrefixLen
		}

		ecs = &ECSOption{
			Family:       family,
			SourcePrefix: prefix,
			ScopePrefix:  DefaultECSClientScope,
			Address:      ip,
		}
	}

	// 回退处理
	if ecs == nil && allowFallback && !forceIPv6 {
		if ip := em.detector.DetectPublicIP(true); ip != nil {
			ecs = &ECSOption{
				Family:       2,
				SourcePrefix: DefaultECSIPv6PrefixLen,
				ScopePrefix:  DefaultECSClientScope,
				Address:      ip,
			}
		}
	}

	// 缓存结果
	if ecs != nil {
		em.cache.Store(cacheKey, ecs)
		time.AfterFunc(IPDetectionCacheExpiry, func() {
			em.cache.Delete(cacheKey)
		})
	}

	return ecs, nil
}
