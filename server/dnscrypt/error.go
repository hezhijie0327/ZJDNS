package dnscrypt

import "errors"

// Sentinel errors for DNSCrypt protocol operations.
var (
	ErrTooShort             = errors.New("dnscrypt: message is too short")
	ErrQueryTooLarge        = errors.New("dnscrypt: query is too large")
	ErrESVersion            = errors.New("dnscrypt: unsupported es-version")
	ErrInvalidDate          = errors.New("dnscrypt: certificate has invalid date range")
	ErrInvalidQuery         = errors.New("dnscrypt: query is invalid and cannot be decrypted")
	ErrInvalidClientMagic   = errors.New("dnscrypt: query contains invalid client magic")
	ErrInvalidResolverMagic = errors.New("dnscrypt: response contains invalid resolver magic")
	ErrInvalidResponse      = errors.New("dnscrypt: response is invalid and cannot be decrypted")
	ErrInvalidPadding       = errors.New("dnscrypt: invalid padding")
	ErrCertTooShort         = errors.New("dnscrypt: certificate is too short")
	ErrCertMagic            = errors.New("dnscrypt: invalid certificate magic")
	ErrClientMagicQUIC      = errors.New("dnscrypt: client magic starts with seven zero bytes — collides with QUIC")
	ErrUnexpectedNonce      = errors.New("dnscrypt: unexpected nonce")
	ErrServerNotStarted     = errors.New("dnscrypt: server is not started")
	ErrServerAlreadyStarted = errors.New("dnscrypt: server is already started")
	ErrPQCertTooShort       = errors.New("dnscrypt: PQ certificate too short")
	ErrPQInvalidProfileExt  = errors.New("dnscrypt: invalid PQ profile extension")
	ErrPQInvalidTicket      = errors.New("dnscrypt: invalid PQ resumption ticket")
	ErrPQTicketExpired      = errors.New("dnscrypt: PQ resumption ticket expired")
)
