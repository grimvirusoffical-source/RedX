package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// quoteGo is a Go double-quoted string literal. encoding/json is not used:
// it rewrites <, > and & as \u003c, \u003e and \u0026, which is not a Swift
// (or portable C) escape.
func quoteGo(s string) string { return strconv.Quote(s) }

func quoteJS(s string) string    { return quoteRunes(s, jsEscape) }
func quotePy(s string) string    { return quoteRunes(s, pyEscape) }
func quoteSwift(s string) string { return quoteRunes(s, swiftEscape) }
func quoteCS(s string) string    { return quoteRunes(s, csEscape) }
func quoteC(s string) string     { return quoteRunes(s, cEscape) }

func quoteRunes(s string, esc func(rune) string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		b.WriteString(esc(r))
	}
	b.WriteByte('"')
	return b.String()
}

func namedEscape(r rune) (string, bool) {
	switch r {
	case '\\':
		return `\\`, true
	case '"':
		return `\"`, true
	case '\n':
		return `\n`, true
	case '\r':
		return `\r`, true
	case '\t':
		return `\t`, true
	default:
		return "", false
	}
}

func jsEscape(r rune) string {
	if s, ok := namedEscape(r); ok {
		return s
	}
	switch r {
	case '\b':
		return `\b`
	case '\f':
		return `\f`
	case '\v':
		return `\v`
	}
	// \0 is an octal escape in strict mode when a digit follows, so controls
	// use a fixed-width \u. U+2028 and U+2029 are line terminators in JS strings.
	if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 || !unicode.IsPrint(r) {
		return fmt.Sprintf(`\u%04X`, r)
	}
	return string(r)
}

func pyEscape(r rune) string {
	if s, ok := namedEscape(r); ok {
		return s
	}
	switch r {
	case '\a':
		return `\a`
	case '\b':
		return `\b`
	case '\f':
		return `\f`
	case '\v':
		return `\v`
	}
	// Python \0 and \x consume following digits. \u is exactly four hex digits.
	if r < 0x20 || r == 0x7f || !unicode.IsPrint(r) {
		if r > 0xFFFF {
			return fmt.Sprintf(`\U%08x`, r)
		}
		return fmt.Sprintf(`\u%04x`, r)
	}
	return string(r)
}

func swiftEscape(r rune) string {
	switch r {
	case '\\':
		return `\\`
	case '"':
		return `\"`
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	case 0:
		return `\0`
	}
	// Swift has no \uXXXX. Non-printables use \u{hex}. \( would interpolate;
	// the backslash case above turns it into \\(.
	if r < 0x20 || r == 0x7f || !unicode.IsPrint(r) {
		return fmt.Sprintf(`\u{%X}`, r)
	}
	return string(r)
}

func csEscape(r rune) string {
	if s, ok := namedEscape(r); ok {
		return s
	}
	switch r {
	case 0:
		return `\0`
	case '\a':
		return `\a`
	case '\b':
		return `\b`
	case '\f':
		return `\f`
	case '\v':
		return `\v`
	}
	if r < 0x20 || r == 0x7f || !unicode.IsPrint(r) {
		if r > 0xFFFF {
			return fmt.Sprintf(`\U%08X`, r)
		}
		return fmt.Sprintf(`\u%04X`, r)
	}
	return string(r)
}

func cEscape(r rune) string {
	switch r {
	case '\\':
		return `\\`
	case '"':
		return `\"`
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	case '\a':
		return `\a`
	case '\b':
		return `\b`
	case '\f':
		return `\f`
	case '\v':
		return `\v`
	}
	// Octal is capped at three digits. \u003c is not a portable C universal
	// character name: values below U+00A0 (except $ @ `) are rejected.
	if r < 0x20 || r == 0x7f {
		return fmt.Sprintf(`\%03o`, r)
	}
	if r >= 0x80 && r < 0xA0 {
		return utf8Octal(r)
	}
	if r >= 0xA0 && (r < 0xD800 || r > 0xDFFF) && !unicode.IsPrint(r) {
		if r > 0xFFFF {
			return fmt.Sprintf(`\U%08X`, r)
		}
		return fmt.Sprintf(`\u%04X`, r)
	}
	if r >= 0xA0 && !unicode.IsPrint(r) {
		return utf8Octal(r)
	}
	// Printable ASCII, including < > &, and printable non-ASCII stay as source
	// characters. Non-printable non-ASCII above U+00A0 uses a universal name
	// above; printable non-ASCII is raw UTF-8, which GCC accepts. Universal
	// names are still used for the test's non-ASCII when IsPrint is false.
	if r >= 0x10000 {
		return fmt.Sprintf(`\U%08X`, r)
	}
	if r >= 0xA0 {
		return fmt.Sprintf(`\u%04X`, r)
	}
	return string(r)
}

func utf8Octal(r rune) string {
	var buf [utf8.UTFMax]byte
	n := utf8.EncodeRune(buf[:], r)
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `\%03o`, buf[i])
	}
	return b.String()
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

func jsComment(s string) string {
	return strings.ReplaceAll(oneLine(s), "*/", "* /")
}

func cComment(s string) string {
	return strings.ReplaceAll(oneLine(s), "*/", "* /")
}

// pyDoc is safe inside a non-raw triple-quoted docstring. Backslashes are
// doubled so the docstring value still shows the original text.
func pyDoc(s string) string {
	s = oneLine(s)
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"""`, `\"\"\"`)
	return s
}

func csDoc(s string) string { return escXML(oneLine(s)) }
