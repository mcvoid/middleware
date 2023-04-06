package logging

import (
	"strings"
	"unicode/utf8"
)

type FormatOptions map[string]string

func Format(format string, options FormatOptions) string {
	// use byte array as a string builder without making
	// too many intermediate objects
	s := []byte{}
	i := 0
	for {
		r, size := utf8.DecodeRuneInString(format[i:])
		// invalid runes and EOF are handled by RuneError
		// so just bail out if we see it.
		if r == utf8.RuneError {
			return string(s)
		}
		i += size

		// unescaped characters just get copied
		if r != '%' {
			s = utf8.AppendRune(s, r)
			continue
		}

		// %% escapes to %
		if strings.HasPrefix(format[i:], "%") {
			s = utf8.AppendRune(s, '%')
			i += len("%")
			continue
		}
		// replace escape sequences with values
		for escape, val := range options {
			if strings.HasPrefix(format[i:], escape) {
				s = append(s, []byte(val)...)
				i += len(escape)
				continue
			}
		}
		// %'s that aren't paired with an escape sequence are just omitted
	}
}
