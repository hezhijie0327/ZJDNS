package dnscryptcrypto

// unpackTxtString unpacks a DNS TXT record value back into the original
// binary certificate bytes.
func UnpackTxtString(s string) (msg []byte) {
	bs := []byte(s)
	msg = make([]byte, 0, len(bs))
	for i := 0; i < len(bs); i++ {
		if bs[i] != '\\' {
			msg = append(msg, bs[i])
			continue
		}
		i++
		if i == len(bs) {
			break
		}
		if i+2 < len(bs) && isDigitSequence(bs[i:i+3]) {
			if b, ok := dddToByte(bs[i:]); ok {
				msg = append(msg, b) //nolint:gosec // G115: dddToByte clamps to 0..255
				i += 2
				continue
			}
			// Out-of-range \DDD escape: reject the whole string rather than
			// silently wrapping the value.
			return nil
		}
		// DNS TXT/master-file escaping (RFC 1035 §5.1) defines \X as the
		// literal character X — there is no \t→TAB mapping; unknown escapes
		// pass through unchanged.
		msg = append(msg, bs[i])
	}
	return msg
}

// isDigitSequence reports whether every byte in seq is an ASCII digit.
func isDigitSequence(seq []byte) (ok bool) {
	for _, c := range seq {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// dddToByte converts three ASCII decimal digits into a byte value.
// Returns ok=false for out-of-range values (\999 wraps in uint8 arithmetic)
// so malformed escapes are rejected instead of silently corrupting bytes.
func dddToByte(s []byte) (res byte, ok bool) {
	n := int(s[0]-'0')*100 + int(s[1]-'0')*10 + int(s[2]-'0')
	if n > 255 {
		return 0, false
	}
	return byte(n), true //nolint:gosec // G115: n clamped to 0..255 above
}
