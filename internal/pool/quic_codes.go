package pool

import "github.com/quic-go/quic-go"

// QUIC application error codes shared across client and server packages.
const (
	// QUICCodeNoError is the QUIC application error code for normal connection
	// closure.
	QUICCodeNoError quic.ApplicationErrorCode = 0

	// QUICCodeInternalError is the QUIC application error code for internal
	// errors.
	QUICCodeInternalError quic.ApplicationErrorCode = 1

	// QUICCodeProtocolError is the QUIC application error code for protocol
	// violations.
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)
