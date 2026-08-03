// Package doq defines DNS-over-QUIC (RFC 9250) application error codes shared
// by the DoQ server (server/protocol/tls) and client (server/upstream/tls)
// packages. It exists so the foundational pool package does not carry a
// transport-layer dependency for two call sites.
package doq

import "github.com/quic-go/quic-go"

// QUIC application error codes (RFC 9000 §20) shared across client and
// server packages.
const (
	// QUICCodeNoError is for normal connection closure (RFC 9250 §4.3).
	QUICCodeNoError quic.ApplicationErrorCode = 0x0

	// QUICCodeInternalError is for internal errors (RFC 9250 §4.3).
	QUICCodeInternalError quic.ApplicationErrorCode = 0x1

	// QUICCodeProtocolError is for protocol violations (RFC 9250 §4.3).
	QUICCodeProtocolError quic.ApplicationErrorCode = 0x2

	// QUICCodeRequestCancelled is for cancelled requests (RFC 9250 §4.3).
	QUICCodeRequestCancelled quic.ApplicationErrorCode = 0x3

	// QUICCodeExcessiveLoad is for load shedding (RFC 9250 §4.3).
	QUICCodeExcessiveLoad quic.ApplicationErrorCode = 0x4

	// QUICCodeUnspecifiedError is for unspecified errors (RFC 9250 §4.3).
	QUICCodeUnspecifiedError quic.ApplicationErrorCode = 0x5

	// QUICCodeErrorReserved is the reserved error code (RFC 9250 §4.3).
	QUICCodeErrorReserved quic.ApplicationErrorCode = 0xd098ea5e
)
