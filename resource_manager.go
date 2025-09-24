package main

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

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
			buf := make([]byte, 0, 1024)
			return &buf
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
	return (*(rm.buffers.Get().(*[]byte)))[:0]
}

func (rm *ResourceManager) PutBuffer(buf []byte) {
	if rm == nil || buf == nil {
		return
	}
	if cap(buf) <= 8192 { // 避免保留过大的buffer
		rm.buffers.Put(&buf)
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
