package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

// encryptedResponse handles encryption and decryption of DNSCrypt server
// responses.
//
// Classical wire format:
//
//	<dnscrypt-response> ::= <resolver-magic> <nonce> <encrypted-response>
//	<encrypted-response> ::= AE(<shared-key>, <nonce>,
//	                           <resolver-response> <resolver-response-pad>)
//
// PQ wire format:
//
//	<pq-response> ::= <resolver-magic> <nonce> <encrypted-response>
//	<encrypted-response> ::= AE(<shared-key>, <nonce>,
//	                           <control-block> <resolver-response> <resolver-response-pad>)
type encryptedResponse struct {
	// esVersion is the cryptographic construction to use.
	esVersion CryptoConstruction

	// nonce is the 24-byte nonce.  The first 12 bytes come from the client
	// query; the remaining 12 bytes are filled by the server.
	nonce Nonce

	// pqControl is the optional PQ response control block (carries a
	// resumption ticket).  Only set for PQ responses.
	pqControl []byte
}

// encrypt encrypts the DNS response packet and returns the wire-format
// response.  r.esVersion and r.nonce must be set beforehand.
func (r *encryptedResponse) encrypt(
	packet []byte,
	sharedKey [SharedKeySize]byte,
	isUDP bool,
) (response []byte, err error) {
	_, _ = rand.Read(r.nonce[12:16])
	binary.BigEndian.PutUint64(r.nonce[16:NonceSize], uint64(time.Now().UnixNano()))

	response = append(response, ResolverMagic...)
	response = append(response, r.nonce[:]...)

	// For PQ responses, prepend the control block to the DNS payload before
	// encryption.
	if r.esVersion.IsPQ() && len(r.pqControl) > 0 {
		controlLen := make([]byte, 2)
		binary.BigEndian.PutUint16(controlLen, uint16(len(r.pqControl))) //nolint:gosec // G115: bounded
		paddedPayload := make([]byte, 0, 2+len(r.pqControl)+len(packet))
		paddedPayload = append(paddedPayload, controlLen...)
		paddedPayload = append(paddedPayload, r.pqControl...)
		paddedPayload = append(paddedPayload, packet...)
		packet = paddedPayload
	}

	padded := pad(packet, isUDP)
	serverNonce := r.nonce

	switch r.esVersion {
	case XChacha20Poly1305, XWingPQ:
		response = xchachaSeal(response, serverNonce[:], padded, sharedKey[:])
	default:
		return nil, ErrESVersion
	}

	return response, nil
}

// decrypt decrypts a wire-format server response and returns the original DNS
// packet.  r.esVersion must be set beforehand.
//
// For PQ responses, the decrypted payload may include a control block which is
// stripped.  The caller can inspect r.pqControl after return.
func (r *encryptedResponse) decrypt(
	response []byte,
	sharedKey [SharedKeySize]byte,
	clientNonce Nonce,
) (packet []byte, err error) {
	headerLength := len(ResolverMagic) + NonceSize
	if len(response) < headerLength+TagSize+minDNSPacketSize {
		return nil, ErrInvalidResponse
	}

	magic := [ResolverMagicSize]byte{}
	copy(magic[:], response[:ResolverMagicSize])
	if !bytes.Equal(magic[:], ResolverMagic) {
		return nil, ErrInvalidResolverMagic
	}

	copy(r.nonce[:], response[ResolverMagicSize:NonceSize+ResolverMagicSize])

	// Verify that the server nonce contains the client's half — this prevents
	// response forgery across different queries.
	if !bytes.Equal(r.nonce[:NonceSize/2], clientNonce[:NonceSize/2]) {
		return nil, ErrUnexpectedNonce
	}

	encrypted := response[NonceSize+ResolverMagicSize:]

	switch r.esVersion {
	case XChacha20Poly1305, XWingPQ:
		packet, err = xchachaOpen(nil, r.nonce[:], encrypted, sharedKey[:])
		if err != nil {
			return nil, fmt.Errorf("decrypting response: %s: %w", r.esVersion, err)
		}
	default:
		return nil, ErrESVersion
	}

	// Strip PQ control block if present.  Validate the control block magic
	// to avoid misinterpreting non-PQ payload bytes as a control block.
	if r.esVersion.IsPQ() && len(packet) >= 2+pqMinControlBlockLen {
		controlLen := int(binary.BigEndian.Uint16(packet[0:2]))
		if controlLen >= pqMinControlBlockLen && 2+controlLen <= len(packet) &&
			bytes.Equal(packet[2:2+len(PQControlMagic)], PQControlMagic[:]) {
			if controlLen > 0 {
				r.pqControl = make([]byte, controlLen)
				copy(r.pqControl, packet[2:2+controlLen])
			}
			packet = packet[2+controlLen:]
		}
	}

	packet, err = unpad(packet)
	if err != nil {
		return nil, fmt.Errorf("removing packet padding: %w", err)
	}

	return packet, nil
}
