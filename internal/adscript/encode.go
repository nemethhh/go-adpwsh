// Package adscript holds the constant PowerShell this library runs, the
// encoder that hands it to pwsh, and the builder for the attribute half of a
// Set-AD* payload.
//
// No Go value is ever formatted into script text. Scripts are constants
// selected by a closed set of op names; every value travels as JSON on stdin
// and is splatted into the cmdlet.
package adscript

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

// EncodeCommand renders script as the UTF-16LE base64 string that
// pwsh -EncodedCommand expects.
func EncodeCommand(script string) string {
	units := utf16.Encode([]rune(script))
	buf := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[i*2:], u)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// DecodeCommand reverses EncodeCommand. It exists for the fake transport and
// for tests, which assert on what would actually run.
func DecodeCommand(encoded string) (string, error) {
	buf, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(buf)%2 != 0 {
		return "", errors.New("adscript: encoded command is not UTF-16LE")
	}
	units := make([]uint16, len(buf)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(buf[i*2:])
	}
	return string(utf16.Decode(units)), nil
}
