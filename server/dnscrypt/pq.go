package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"

	"github.com/cloudflare/circl/kem/xwing"
	"golang.org/x/crypto/hkdf"
)

func hkdfSha256(salt, ikm, info []byte, outLen int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, outLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func pqProfileExtension() []byte {
	ext := make([]byte, PQProfileExtSize)
	copy(ext[0:3], "PQD")
	ext[3] = 0x01
	ext[4] = PQESVersion[0]
	ext[5] = PQESVersion[1]
	ext[6] = 0x01
	ext[7] = 0x01
	binary.BigEndian.PutUint16(ext[8:10], PQPublicKeySize)
	binary.BigEndian.PutUint16(ext[10:12], PQCiphertextSize)
	return ext
}

func pqCertContext(binCert []byte) []byte {
	ctx := make([]byte, 0, 14+
		2+2+ // es-version + minor
		certPQPkLen+ClientMagicSize+
		4+4+4+ // serial + ts-start + ts-end
		certPQExtLen)
	ctx = append(ctx, "DNSCrypt-PQ-v1"...)
	ctx = append(ctx, binCert[certESVersionOff:certESVersionOff+2]...)           // es-version
	ctx = append(ctx, binCert[certMinorOff:certMinorOff+2]...)                   // protocol-minor-version
	ctx = append(ctx, binCert[certPQPkOff:certPQPkOff+certPQPkLen]...)           // resolver-pk
	ctx = append(ctx, binCert[certPQMagicOff:certPQMagicOff+ClientMagicSize]...) // client-magic
	ctx = append(ctx, binCert[certPQSerialOff:certPQSerialOff+4]...)             // serial
	ctx = append(ctx, binCert[certPQTSOff:certPQTSOff+4]...)                     // ts-start
	ctx = append(ctx, binCert[certPQTEEnd:certPQTEEnd+4]...)                     // ts-end
	ctx = append(ctx, binCert[certPQExtOff:certPQExtOff+certPQExtLen]...)        // extensions
	return ctx
}

func pqDeriveSharedKey(kemSS []byte, clientMagic [8]byte, certContext, ct []byte) [SharedKeySize]byte {
	salt := make([]byte, 0, 10)
	salt = append(salt, PQESVersion[0], PQESVersion[1])
	salt = append(salt, clientMagic[:]...)
	info := make([]byte, 0, len(certContext)+len(ct))
	info = append(info, certContext...)
	info = append(info, ct...)
	var key [SharedKeySize]byte
	// hkdfSha256 on SHA-256 cannot fail in practice.
	hkdfOut, _ := hkdfSha256(salt, kemSS, info, SharedKeySize)
	copy(key[:], hkdfOut)
	return key
}

func pqResumeSecret(sharedKey [SharedKeySize]byte, clientMagic [8]byte, clientNonce []byte) [SharedKeySize]byte {
	salt := make([]byte, 0, 8+len(clientNonce))
	salt = append(salt, clientMagic[:]...)
	salt = append(salt, clientNonce...)
	var out [SharedKeySize]byte
	// hkdfSha256 on SHA-256 cannot fail in practice.
	hkdfOut, _ := hkdfSha256(salt, sharedKey[:], []byte("DNSCrypt-PQ-resume-secret-v1"), SharedKeySize)
	copy(out[:], hkdfOut)
	return out
}

func pqResumedSharedKey(resumeSecret [SharedKeySize]byte, clientMagic [8]byte, clientNonce, ticket []byte) [SharedKeySize]byte {
	salt := make([]byte, 0, 8+len(clientNonce))
	salt = append(salt, clientMagic[:]...)
	salt = append(salt, clientNonce...)
	th := sha256.Sum256(ticket)
	info := make([]byte, 0, 27+32)
	info = append(info, "DNSCrypt-PQ-resumed-query-v1"...)
	info = append(info, th[:]...)
	var key [SharedKeySize]byte
	// hkdfSha256 on SHA-256 cannot fail in practice.
	hkdfOut, _ := hkdfSha256(salt, resumeSecret[:], info, SharedKeySize)
	copy(key[:], hkdfOut)
	return key
}

func pqEncapsulate(pk []byte) (kemSS, ct []byte, err error) {
	return xwing.Encapsulate(pk, nil)
}

func pqDecapsulate(ct, sk []byte) (kemSS []byte) {
	return xwing.Decapsulate(ct, sk)
}

func pqGenKeyPair() (publicKey, privateKey []byte, err error) {
	sk, pk, err := xwing.GenerateKeyPairPacked(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

// ---------------------------------------------------------------------------
// Ticket encryption (server-side)
// ---------------------------------------------------------------------------

func pqSealTicket(key *[xchachaKeySize]byte, nonce *[xchachaNonceSize]byte, plaintext []byte) []byte {
	ct := xchachaSeal(nil, nonce[:], plaintext, key[:])
	out := make([]byte, xchachaNonceSize+len(ct))
	copy(out[:xchachaNonceSize], nonce[:])
	copy(out[xchachaNonceSize:], ct)
	return out
}

func pqOpenTicket(key *[xchachaKeySize]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < xchachaNonceSize {
		return nil, ErrPQInvalidTicket
	}
	var nonce [xchachaNonceSize]byte
	copy(nonce[:], ciphertext[:xchachaNonceSize])
	return xchachaOpen(nil, nonce[:], ciphertext[xchachaNonceSize:], key[:])
}

// ---------------------------------------------------------------------------
// Control block (response-side)
// ---------------------------------------------------------------------------

func pqBuildControlBlock(ticket []byte, lifetime uint32) []byte {
	blockLen := 4 + 1 + 4 + 2 + len(ticket)
	buf := make([]byte, blockLen)
	copy(buf[0:4], PQControlMagic[:])
	buf[4] = 0x01
	binary.BigEndian.PutUint32(buf[5:9], lifetime)
	binary.BigEndian.PutUint16(buf[9:11], uint16(len(ticket))) //nolint:gosec // G115: ticket length bounded
	copy(buf[11:], ticket)
	return buf
}

func pqParseControlBlock(control []byte) (ticket []byte, lifetime uint32, err error) {
	if len(control) < 11 {
		return nil, 0, ErrPQInvalidTicket
	}
	if !bytes.Equal(control[0:4], PQControlMagic[:]) || control[4] != 0x01 {
		return nil, 0, ErrPQInvalidTicket
	}
	lifetime = binary.BigEndian.Uint32(control[5:9])
	ticketLen := int(binary.BigEndian.Uint16(control[9:11]))
	if 11+ticketLen > len(control) {
		return nil, 0, ErrPQInvalidTicket
	}
	ticket = make([]byte, ticketLen)
	copy(ticket, control[11:11+ticketLen])
	return ticket, lifetime, nil
}

// ---------------------------------------------------------------------------
// Padding
// ---------------------------------------------------------------------------

func pqPad(packet []byte, floor int) []byte {
	padded := make([]byte, len(packet), len(packet)+64)
	copy(padded, packet)
	padded = append(padded, 0x80)
	target := (len(padded) + 63) &^ 63
	if target < floor {
		target = floor
	}
	for len(padded) < target {
		padded = append(padded, 0)
	}
	return padded
}

// ---------------------------------------------------------------------------
// Ticket plaintext encoding (server-side)
// ---------------------------------------------------------------------------

func encodeTicketPlaintext(clientMagic [ClientMagicSize]byte, resumeSecret [SharedKeySize]byte, expiry time.Time) []byte {
	buf := make([]byte, ticketPlaintextSize)
	copy(buf[ticketPlaintextESOff:ticketPlaintextESOff+ticketPlaintextESLen], PQESVersion[:])
	copy(buf[ticketPlaintextMagicOff:ticketPlaintextMagicOff+ticketPlaintextMagicLen], clientMagic[:])
	copy(buf[ticketPlaintextSecretOff:ticketPlaintextSecretOff+ticketPlaintextSecretLen], resumeSecret[:])
	binary.BigEndian.PutUint64(buf[ticketPlaintextExpiryOff:ticketPlaintextExpiryOff+ticketPlaintextExpiryLen], uint64(expiry.Unix())) //nolint:gosec // G115: expiry is a valid timestamp
	return buf
}

func decodeTicketPlaintext(plaintext []byte) (clientMagic [ClientMagicSize]byte, resumeSecret [SharedKeySize]byte, expiry time.Time, err error) {
	if len(plaintext) < ticketPlaintextSize {
		return [ClientMagicSize]byte{}, [SharedKeySize]byte{}, time.Time{}, ErrPQInvalidTicket
	}
	copy(clientMagic[:], plaintext[ticketPlaintextMagicOff:ticketPlaintextMagicOff+ticketPlaintextMagicLen])
	copy(resumeSecret[:], plaintext[ticketPlaintextSecretOff:ticketPlaintextSecretOff+ticketPlaintextSecretLen])
	exp := binary.BigEndian.Uint64(plaintext[ticketPlaintextExpiryOff : ticketPlaintextExpiryOff+ticketPlaintextExpiryLen])
	return clientMagic, resumeSecret, time.Unix(int64(exp), 0), nil //nolint:gosec // G115: expiry is a valid Unix timestamp
}
