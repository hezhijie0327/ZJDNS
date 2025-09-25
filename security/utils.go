package security

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"

	"github.com/quic-go/quic-go"
)

// NewSecureConnErrorHandler 创建新的安全连接错误处理器
func NewSecureConnErrorHandler() *SecureConnErrorHandler {
	return &SecureConnErrorHandler{}
}

// IsRetryableError 检查错误是否可重试
func (h *SecureConnErrorHandler) IsRetryableError(protocol string, err error) bool {
	if h == nil || err == nil {
		return false
	}

	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	protocol = strings.ToLower(protocol)

	switch protocol {
	case "quic", "http3":
		return h.handleQUICErrors(err)
	case "tls":
		return h.handleTLSErrors(err)
	case "https":
		return h.handleHTTPErrors(err)
	default:
		return false
	}
}

// handleQUICErrors 处理QUIC错误
func (h *SecureConnErrorHandler) handleQUICErrors(err error) bool {
	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) {
		return qAppErr.ErrorCode == 0 || qAppErr.ErrorCode == quic.ApplicationErrorCode(0x100)
	}

	var qIdleErr *quic.IdleTimeoutError
	if errors.As(err, &qIdleErr) {
		return true
	}

	var resetErr *quic.StatelessResetError
	if errors.As(err, &resetErr) {
		return true
	}

	var qTransportError *quic.TransportError
	if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError {
		return true
	}

	return errors.Is(err, quic.Err0RTTRejected)
}

// handleTLSErrors 处理TLS错误
func (h *SecureConnErrorHandler) handleTLSErrors(err error) bool {
	errStr := err.Error()
	connectionErrors := []string{
		"broken pipe", "connection reset", "use of closed network connection",
		"connection refused", "no route to host", "network is unreachable",
	}

	for _, connErr := range connectionErrors {
		if strings.Contains(errStr, connErr) {
			return true
		}
	}

	return errors.Is(err, io.EOF)
}

func (h *SecureConnErrorHandler) handleHTTPErrors(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return h.handleQUICErrors(err)
}

var globalSecureConnErrorHandler = NewSecureConnErrorHandler()

// GlobalSecureConnErrorHandler 全局安全连接错误处理器
var GlobalSecureConnErrorHandler = globalSecureConnErrorHandler
