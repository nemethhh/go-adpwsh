package addn

func mustEscape(c byte) bool {
	return c > 0x7f || c == '(' || c == ')' || c == '\\' || c == '*' || c == 0
}

// EscapeFilter escapes the RFC 4515 special set `()*\` and every byte outside
// 0 < c < 0x80 in an assertion value. Every value this library puts inside an
// -LDAPFilter goes through here; hand-rolled quoting is the defect class the
// design exists to retire.
func EscapeFilter(filter string) string {
	const hexValues = "0123456789abcdef"
	escapes := 0
	for i := 0; i < len(filter); i++ {
		if mustEscape(filter[i]) {
			escapes++
		}
	}
	if escapes == 0 {
		return filter
	}
	buf := make([]byte, len(filter)+escapes*2)
	for i, j := 0, 0; i < len(filter); i++ {
		c := filter[i]
		if mustEscape(c) {
			buf[j], buf[j+1], buf[j+2] = '\\', hexValues[c>>4], hexValues[c&0xf]
			j += 3
			continue
		}
		buf[j] = c
		j++
	}
	return string(buf)
}
