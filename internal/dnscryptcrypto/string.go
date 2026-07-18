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
			msg = append(msg, dddToByte(bs[i:]))
			i += 2
			continue
		}
		msg = append(msg, unescapeChar(bs[i]))
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
func dddToByte(s []byte) (res byte) {
	return (s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0')
}

// unescapeChar returns the byte corresponding to the escaped character.
// If b is not a recognized escape, it is returned as-is.
func unescapeChar(b byte) (escaped byte) {
	switch b {
	case 't':
		return '\t'
	case 'r':
		return '\r'
	case 'n':
		return '\n'
	default:
		return b
	}
}
