package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/xwing"
	"golang.org/x/crypto/hkdf"
)

func hkdfSha256(salt, ikm, info []byte, outLen int) []byte {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, outLen)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
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
	ctx := make([]byte, 0, 14+2+2+PQPublicKeySize+8+4+4+4+PQProfileExtSize)
	ctx = append(ctx, "DNSCrypt-PQ-v1"...)
	ctx = append(ctx, binCert[4:6]...)
	ctx = append(ctx, binCert[6:8]...)
	ctx = append(ctx, binCert[72:1288]...)
	ctx = append(ctx, binCert[1288:1296]...)
	ctx = append(ctx, binCert[1296:1300]...)
	ctx = append(ctx, binCert[1300:1304]...)
	ctx = append(ctx, binCert[1304:1308]...)
	ctx = append(ctx, binCert[1308:1320]...)
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
	copy(key[:], hkdfSha256(salt, kemSS, info, SharedKeySize))
	return key
}

func pqResumeSecret(sharedKey [SharedKeySize]byte, clientMagic [8]byte, clientNonce []byte) [SharedKeySize]byte {
	salt := make([]byte, 0, 8+len(clientNonce))
	salt = append(salt, clientMagic[:]...)
	salt = append(salt, clientNonce...)
	var out [SharedKeySize]byte
	copy(out[:], hkdfSha256(salt, sharedKey[:], []byte("DNSCrypt-PQ-resume-secret-v1"), SharedKeySize))
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
	copy(key[:], hkdfSha256(salt, resumeSecret[:], info, SharedKeySize))
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
// Resumption state
// ---------------------------------------------------------------------------

type pqResumptionState struct {
	mu           sync.Mutex
	ticket       []byte
	resumeSecret [SharedKeySize]byte
	expiry       time.Time
	epoch        uint64
}

func newPqResumptionState() *pqResumptionState {
	return &pqResumptionState{}
}

func (s *pqResumptionState) store(ticket []byte, resumeSecret [SharedKeySize]byte, expiry time.Time, epoch uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ticket = append([]byte(nil), ticket...)
	s.resumeSecret = resumeSecret
	s.expiry = expiry
	s.epoch = epoch
}

func (s *pqResumptionState) get(currentEpoch uint64) (ticket []byte, resumeSecret [SharedKeySize]byte, ok bool) {
	if s == nil {
		return nil, [SharedKeySize]byte{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ticket == nil || !time.Now().Before(s.expiry) {
		return nil, [SharedKeySize]byte{}, false
	}
	if s.epoch != currentEpoch {
		s.ticket = nil
		s.resumeSecret = [SharedKeySize]byte{}
		s.expiry = time.Time{}
		return nil, [SharedKeySize]byte{}, false
	}
	return append([]byte(nil), s.ticket...), s.resumeSecret, true
}

// ---------------------------------------------------------------------------
// Ticket encryption (server-side)
// ---------------------------------------------------------------------------

func pqSealTicket(key *[xchachaKeySize]byte, nonce *[24]byte, plaintext []byte) []byte {
	return xchachaSeal(nil, nonce[:], plaintext, key[:])
}

func pqOpenTicket(key *[xchachaKeySize]byte, nonce *[24]byte, ciphertext []byte) ([]byte, error) {
	return xchachaOpen(nil, nonce[:], ciphertext, key[:])
}

// ---------------------------------------------------------------------------
// Control block (response-side)
// ---------------------------------------------------------------------------

func pqBuildControlBlock(ticket []byte, lifetime uint32) []byte {
	blockLen := 2 + 4 + 1 + 4 + 2 + len(ticket)
	buf := make([]byte, blockLen)
	binary.BigEndian.PutUint16(buf[0:2], uint16(blockLen-2)) //nolint:gosec // G115: control block length bounded
	copy(buf[2:6], PQControlMagic[:])
	buf[6] = 0x01
	binary.BigEndian.PutUint32(buf[7:11], lifetime)
	binary.BigEndian.PutUint16(buf[11:13], uint16(len(ticket))) //nolint:gosec // G115: ticket length bounded
	copy(buf[13:], ticket)
	return buf
}

func pqParseControlBlock(control []byte) (ticket []byte, lifetime uint32, err error) {
	if len(control) < 13 {
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
	buf := make([]byte, 2+8+32+8)
	copy(buf[0:2], PQESVersion[:])
	copy(buf[2:10], clientMagic[:])
	copy(buf[10:42], resumeSecret[:])
	binary.BigEndian.PutUint64(buf[42:50], uint64(expiry.Unix())) //nolint:gosec // G115: expiry is a valid timestamp
	return buf
}

func decodeTicketPlaintext(plaintext []byte) (clientMagic [ClientMagicSize]byte, resumeSecret [SharedKeySize]byte, expiry time.Time, err error) {
	if len(plaintext) < 50 {
		return [ClientMagicSize]byte{}, [SharedKeySize]byte{}, time.Time{}, ErrPQInvalidTicket
	}
	copy(clientMagic[:], plaintext[2:10])
	copy(resumeSecret[:], plaintext[10:42])
	exp := binary.BigEndian.Uint64(plaintext[42:50])
	return clientMagic, resumeSecret, time.Unix(int64(exp), 0), nil //nolint:gosec // G115: expiry is a valid Unix timestamp
}
