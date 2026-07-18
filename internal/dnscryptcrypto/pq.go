package dnscryptcrypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/cloudflare/circl/kem/xwing"
	"golang.org/x/crypto/hkdf"
)

func HKDFSHA256(salt, ikm, info []byte, outLen int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, outLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func PQProfileExtension() []byte {
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

func PQCertContext(binCert []byte) []byte {
	ctx := make([]byte, 0, 14+
		2+2+ // es-version + minor
		CertPQPkLen+ClientMagicSize+
		4+4+4+ // serial + ts-start + ts-end
		CertPQExtLen)
	ctx = append(ctx, "DNSCrypt-PQ-v1"...)
	ctx = append(ctx, binCert[CertESVersionOff:CertESVersionOff+2]...)           // es-version
	ctx = append(ctx, binCert[CertMinorOff:CertMinorOff+2]...)                   // protocol-minor-version
	ctx = append(ctx, binCert[CertPQPkOff:CertPQPkOff+CertPQPkLen]...)           // resolver-pk
	ctx = append(ctx, binCert[CertPQMagicOff:CertPQMagicOff+ClientMagicSize]...) // client-magic
	ctx = append(ctx, binCert[CertPQSerialOff:CertPQSerialOff+4]...)             // serial
	ctx = append(ctx, binCert[CertPQTSOff:CertPQTSOff+4]...)                     // ts-start
	ctx = append(ctx, binCert[CertPQTEEnd:CertPQTEEnd+4]...)                     // ts-end
	ctx = append(ctx, binCert[CertPQExtOff:CertPQExtOff+CertPQExtLen]...)        // extensions
	return ctx
}

func PQDeriveSharedKey(kemSS []byte, clientMagic [8]byte, certContext, ct []byte) [SharedKeySize]byte {
	salt := make([]byte, 0, 10)
	salt = append(salt, PQESVersion[0], PQESVersion[1])
	salt = append(salt, clientMagic[:]...)
	info := make([]byte, 0, len(certContext)+len(ct))
	info = append(info, certContext...)
	info = append(info, ct...)
	var key [SharedKeySize]byte
	// hkdfSha256 on SHA-256 cannot fail in practice.
	hkdfOut, _ := HKDFSHA256(salt, kemSS, info, SharedKeySize)
	copy(key[:], hkdfOut)
	return key
}

func PQResumeSecret(sharedKey [SharedKeySize]byte, clientMagic [8]byte, clientNonce []byte) [SharedKeySize]byte {
	salt := make([]byte, 0, 8+len(clientNonce))
	salt = append(salt, clientMagic[:]...)
	salt = append(salt, clientNonce...)
	var out [SharedKeySize]byte
	// hkdfSha256 on SHA-256 cannot fail in practice.
	hkdfOut, _ := HKDFSHA256(salt, sharedKey[:], []byte("DNSCrypt-PQ-resume-secret-v1"), SharedKeySize)
	copy(out[:], hkdfOut)
	return out
}

func PQResumedSharedKey(resumeSecret [SharedKeySize]byte, clientMagic [8]byte, clientNonce, ticket []byte) [SharedKeySize]byte {
	salt := make([]byte, 0, 8+len(clientNonce))
	salt = append(salt, clientMagic[:]...)
	salt = append(salt, clientNonce...)
	th := sha256.Sum256(ticket)
	info := make([]byte, 0, 27+32)
	info = append(info, "DNSCrypt-PQ-resumed-query-v1"...)
	info = append(info, th[:]...)
	var key [SharedKeySize]byte
	// hkdfSha256 on SHA-256 cannot fail in practice.
	hkdfOut, _ := HKDFSHA256(salt, resumeSecret[:], info, SharedKeySize)
	copy(key[:], hkdfOut)
	return key
}

func PQEncapsulate(pk []byte) (kemSS, ct []byte, err error) {
	return xwing.Encapsulate(pk, nil)
}

func PQDecapsulate(ct, sk []byte) (kemSS []byte) {
	return xwing.Decapsulate(ct, sk)
}

func PQGenKeyPair() (publicKey, privateKey []byte, err error) {
	sk, pk, err := xwing.GenerateKeyPairPacked(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

// DerivePQKeys deterministically derives an X-Wing keypair from an X25519
// secret key seed, matching the official encrypted-dns-server derivation:
//
//	pq_seed = SHA-256("DNSCrypt-PQ-seed-v1" || resolver_sk_seed)
//	xwing_sk, xwing_pk = xwing.DeriveKeyPairPacked(pq_seed)
func DerivePQKeys(classicalSk []byte) (pk, sk []byte) {
	input := make([]byte, 0, 25+len(classicalSk))
	input = append(input, "DNSCrypt-PQ-seed-v1"...)
	input = append(input, classicalSk...)
	seed := sha256.Sum256(input)
	sk, pk = xwing.DeriveKeyPairPacked(seed[:])
	return pk, sk
}

// ---------------------------------------------------------------------------
// Ticket encryption (server-side)
// ---------------------------------------------------------------------------

func PQSealTicket(key *[XchachaKeySize]byte, keyID *[TicketKeyIDSize]byte, nonce *[XchachaNonceSize]byte, plaintext []byte) []byte {
	ct := XchachaSeal(nil, nonce[:], plaintext, key[:])
	out := make([]byte, TicketKeyIDSize+XchachaNonceSize+len(ct))
	copy(out[:TicketKeyIDSize], keyID[:])
	copy(out[TicketKeyIDSize:TicketKeyIDSize+XchachaNonceSize], nonce[:])
	copy(out[TicketKeyIDSize+XchachaNonceSize:], ct)
	return out
}

func PQOpenTicket(key *[XchachaKeySize]byte, keyID *[TicketKeyIDSize]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < TicketKeyIDSize+XchachaNonceSize+TagSize {
		return nil, ErrPQInvalidTicket
	}
	if !bytes.Equal(ciphertext[:TicketKeyIDSize], keyID[:]) {
		return nil, ErrPQInvalidTicket
	}
	var nonce [XchachaNonceSize]byte
	copy(nonce[:], ciphertext[TicketKeyIDSize:TicketKeyIDSize+XchachaNonceSize])
	return XchachaOpen(nil, nonce[:], ciphertext[TicketKeyIDSize+XchachaNonceSize:], key[:])
}

// ---------------------------------------------------------------------------
// Control block (response-side)
// ---------------------------------------------------------------------------

func PQBuildControlBlock(ticket []byte, lifetime uint32) []byte {
	blockLen := 4 + 1 + 4 + 2 + len(ticket)
	buf := make([]byte, blockLen)
	copy(buf[0:4], PQControlMagic[:])
	buf[4] = 0x01
	binary.BigEndian.PutUint32(buf[5:9], lifetime)
	binary.BigEndian.PutUint16(buf[9:11], uint16(len(ticket))) //nolint:gosec // G115: ticket length bounded
	copy(buf[11:], ticket)
	return buf
}

func PQParseControlBlock(control []byte) (ticket []byte, lifetime uint32, err error) {
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

func PQPad(packet []byte, floor int) []byte {
	padded := make([]byte, len(packet), len(packet)+64)
	copy(padded, packet)
	padded = append(padded, 0x80)
	target := max((len(padded)+63)&^63, floor)
	for len(padded) < target {
		padded = append(padded, 0)
	}
	return padded
}

// ---------------------------------------------------------------------------
// Ticket plaintext encoding (server-side)
// ---------------------------------------------------------------------------

func ProfileExtensionHash() [32]byte {
	return sha256.Sum256(PQProfileExtension())
}

func EncodeTicketPlaintext(resumeSecret [SharedKeySize]byte, clientMagic [ClientMagicSize]byte, serial, tsEnd, expiry uint32, peHash [32]byte) []byte {
	buf := make([]byte, TicketPlaintextSize)
	copy(buf[TicketPlaintextSecretOff:TicketPlaintextSecretOff+TicketPlaintextSecretLen], resumeSecret[:])
	copy(buf[TicketPlaintextESOff:TicketPlaintextESOff+TicketPlaintextESLen], PQESVersion[:])
	copy(buf[TicketPlaintextMagicOff:TicketPlaintextMagicOff+TicketPlaintextMagicLen], clientMagic[:])
	binary.BigEndian.PutUint32(buf[TicketPlaintextSerialOff:TicketPlaintextSerialOff+TicketPlaintextSerialLen], serial)
	binary.BigEndian.PutUint32(buf[TicketPlaintextTSEndOff:TicketPlaintextTSEndOff+TicketPlaintextTSEndLen], tsEnd)
	binary.BigEndian.PutUint32(buf[TicketPlaintextExpiryOff:TicketPlaintextExpiryOff+TicketPlaintextExpiryLen], expiry)
	copy(buf[TicketPlaintextPEHashOff:TicketPlaintextPEHashOff+TicketPlaintextPEHashLen], peHash[:])
	return buf
}

func DecodeTicketPlaintext(plaintext []byte) (clientMagic [ClientMagicSize]byte, resumeSecret [SharedKeySize]byte, ticketExpiry uint32, err error) {
	if len(plaintext) < TicketPlaintextSize {
		return [ClientMagicSize]byte{}, [SharedKeySize]byte{}, 0, ErrPQInvalidTicket
	}
	copy(resumeSecret[:], plaintext[TicketPlaintextSecretOff:TicketPlaintextSecretOff+TicketPlaintextSecretLen])
	copy(clientMagic[:], plaintext[TicketPlaintextMagicOff:TicketPlaintextMagicOff+TicketPlaintextMagicLen])
	ticketExpiry = binary.BigEndian.Uint32(plaintext[TicketPlaintextExpiryOff : TicketPlaintextExpiryOff+TicketPlaintextExpiryLen])
	return clientMagic, resumeSecret, ticketExpiry, nil
}
