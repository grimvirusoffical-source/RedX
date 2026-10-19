package query

import (
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// BoxQL uses the lexical rules of Box files (docs/box-grammar.md section 1): whitespace, <<comments>>,
// "strings" with JSON escapes, numbers, identifiers that may contain "-" and "_". It adds the
// operators of the query language and $name parameters.

type tokKind uint8

const (
	tEOF tokKind = iota
	tIdent
	tString // "string literal"
	tNumber
	tParam // $name
	tPunct
)

type token struct {
	kind tokKind
	text string // ident/string content, param name, punct text, number source text
	num  float64
	pos  Pos
	end  int // byte offset after the token
}

func (t token) describe() string {
	switch t.kind {
	case tEOF:
		return "the end of the query"
	case tIdent:
		return "`" + t.text + "`"
	case tString:
		return "a string"
	case tNumber:
		return "number " + t.text
	case tParam:
		return "parameter $" + t.text
	}
	return "`" + t.text + "`"
}

type lexer struct {
	src  string
	i    int
	line int
	col  int
	max  int

	prevOperand bool // the previous token ends an operand, so "-" is an operator, not a sign
}

func (l *lexer) pos() Pos { return Pos{Offset: l.i, Line: l.line, Col: l.col} }

func (l *lexer) advance(n int) {
	for k := 0; k < n && l.i < len(l.src); {
		r, sz := utf8.DecodeRuneInString(l.src[l.i:])
		l.i += sz
		k += sz
		if r == '\n' {
			l.line++
			l.col = 1
		} else {
			l.col++
		}
	}
}

func isIdentStart(r rune) bool { return r == '_' || unicode.IsLetter(r) }
func isIdentPart(r rune) bool  { return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) }

// lex splits src into tokens. It enforces maxTokens.
func lex(src string, maxTokens int) ([]token, error) {
	if !utf8.ValidString(src) {
		bad := 0
		for i := 0; i < len(src); {
			r, sz := utf8.DecodeRuneInString(src[i:])
			if r == utf8.RuneError && sz == 1 {
				bad = i
				break
			}
			i += sz
		}
		l := lexer{src: src, line: 1, col: 1}
		l.advance(bad)
		return nil, &SyntaxError{Pos: l.pos(), Msg: "invalid UTF-8"}
	}
	l := &lexer{src: src, line: 1, col: 1, max: maxTokens}
	var toks []token
	for {
		t, err := l.next()
		if err != nil {
			return nil, err
		}
		toks = append(toks, t)
		switch t.kind {
		case tIdent, tString, tNumber, tParam:
			l.prevOperand = true
		case tPunct:
			l.prevOperand = t.text == ")" || t.text == "]"
		}
		if t.kind == tEOF {
			return toks, nil
		}
		if maxTokens > 0 && len(toks) > maxTokens {
			return nil, &SyntaxError{Pos: t.pos, Msg: "query has too many tokens (limit " + strconv.Itoa(maxTokens) + ")"}
		}
	}
}

// skipSpace skips whitespace and << comments >>.
func (l *lexer) skipSpace() error {
	for l.i < len(l.src) {
		c := l.src[l.i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			l.advance(1)
		case c == '<' && strings.HasPrefix(l.src[l.i:], "<<"):
			start := l.pos()
			end := strings.Index(l.src[l.i+2:], ">>")
			if end < 0 {
				return &SyntaxError{Pos: start, Msg: "unterminated comment (missing closing >>)"}
			}
			l.advance(2 + end + 2)
		default:
			return nil
		}
	}
	return nil
}

func (l *lexer) next() (token, error) {
	if err := l.skipSpace(); err != nil {
		return token{}, err
	}
	start := l.pos()
	mk := func(k tokKind, text string, n int) token {
		l.advance(n)
		return token{kind: k, text: text, pos: start, end: l.i}
	}
	if l.i >= len(l.src) {
		return token{kind: tEOF, pos: start, end: l.i}, nil
	}
	c := l.src[l.i]
	rest := l.src[l.i:]
	switch {
	case c == '"':
		return l.str(start)
	case c >= '0' && c <= '9':
		return l.number(start, 0)
	case c == '-' && len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9' && !l.prevOperand:
		return l.number(start, 1)
	case c == '$':
		j := 1
		for j < len(rest) {
			b := rest[j]
			if b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (j > 1 && b >= '0' && b <= '9') {
				j++
				continue
			}
			break
		}
		if j == 1 {
			return token{}, &SyntaxError{Pos: start, Msg: "a parameter needs a name: $name (letters, digits and _)", Near: "$"}
		}
		if j > 65 {
			return token{}, &SyntaxError{Pos: start, Msg: "parameter name longer than 64 bytes"}
		}
		return mk(tParam, rest[1:j], j), nil
	}
	r, _ := utf8.DecodeRuneInString(rest)
	if isIdentStart(r) {
		j := 0
		for j < len(rest) {
			r, sz := utf8.DecodeRuneInString(rest[j:])
			if isIdentPart(r) {
				j += sz
				continue
			}
			// a hyphen belongs to the name only between name characters ("red-xai", not "Foo->")
			if r == '-' && j+1 < len(rest) {
				if r2, _ := utf8.DecodeRuneInString(rest[j+1:]); isIdentPart(r2) {
					j += sz
					continue
				}
			}
			break
		}
		if j > 256 {
			return token{}, &SyntaxError{Pos: start, Msg: "name longer than 256 bytes"}
		}
		return mk(tIdent, rest[:j], j), nil
	}
	for _, p := range []string{"@!>", "@>", "->", "<=", ">=", "!=", ".."} {
		if strings.HasPrefix(rest, p) {
			return mk(tPunct, p, len(p)), nil
		}
	}
	switch c {
	case '{', '}', '[', ']', '(', ')', '=', ',', ';', ':', '.', '~', '*', '!', '<', '>', '+', '-', '/', '|', '&', '?':
		return mk(tPunct, string(c), 1), nil
	case '@':
		return token{}, &SyntaxError{Pos: start, Msg: "`@` must be part of a link operator (@> or @!>); (N@T) expiry markers are not allowed in queries", Near: "@"}
	case '\'':
		return token{}, &SyntaxError{Pos: start, Msg: "strings use double quotes: \"text\"", Near: "'"}
	case '%', '^', '#', '\\', '`':
		return token{}, &SyntaxError{Pos: start, Msg: "unexpected character", Near: string(c)}
	}
	if c < 0x20 || c == 0x7f {
		return token{}, &SyntaxError{Pos: start, Msg: "unexpected control character"}
	}
	return token{}, &SyntaxError{Pos: start, Msg: "unexpected character", Near: string(r)}
}

// str lexes a "string" with the Box escapes: \" \\ \/ \n \r \t \b \f \uXXXX.
func (l *lexer) str(start Pos) (token, error) {
	var sb strings.Builder
	j := l.i + 1
	for j < len(l.src) {
		c := l.src[j]
		switch {
		case c == '"':
			l.advance(j + 1 - l.i)
			return token{kind: tString, text: sb.String(), pos: start, end: l.i}, nil
		case c == 0:
			l.advance(j - l.i)
			return token{}, &SyntaxError{Pos: l.pos(), Msg: "NUL byte in string"}
		case c == '\\':
			if j+1 >= len(l.src) {
				break
			}
			e := l.src[j+1]
			switch e {
			case '"', '\\', '/':
				sb.WriteByte(e)
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'u':
				if j+6 > len(l.src) {
					l.advance(j - l.i)
					return token{}, &SyntaxError{Pos: l.pos(), Msg: "\\u needs four hex digits"}
				}
				n, err := strconv.ParseUint(l.src[j+2:j+6], 16, 32)
				if err != nil {
					l.advance(j - l.i)
					return token{}, &SyntaxError{Pos: l.pos(), Msg: "\\u needs four hex digits", Near: l.src[j : j+6]}
				}
				sb.WriteRune(rune(n))
				j += 4
			default:
				l.advance(j - l.i)
				return token{}, &SyntaxError{Pos: l.pos(), Msg: "unknown escape in string", Near: l.src[j : j+2]}
			}
			j += 2
			continue
		default:
			sb.WriteByte(c)
		}
		j++
	}
	return token{}, &SyntaxError{Pos: start, Msg: "unterminated string (missing closing \")"}
}

func (l *lexer) number(start Pos, sign int) (token, error) {
	s := l.src[l.i+sign:]
	j := 0
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	// fraction: only when a digit follows the dot (so 1..5 is a range and 1.x is not a number)
	if j+1 < len(s) && s[j] == '.' && s[j+1] >= '0' && s[j+1] <= '9' {
		j++
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
	}
	if j < len(s) && (s[j] == 'e' || s[j] == 'E') {
		k := j + 1
		if k < len(s) && (s[k] == '+' || s[k] == '-') {
			k++
		}
		if k < len(s) && s[k] >= '0' && s[k] <= '9' {
			for k < len(s) && s[k] >= '0' && s[k] <= '9' {
				k++
			}
			j = k
		}
	}
	if j < len(s) {
		if r, _ := utf8.DecodeRuneInString(s[j:]); isIdentStart(r) {
			return token{}, &SyntaxError{Pos: start, Msg: "malformed number", Near: l.src[l.i : l.i+sign+j+1]}
		}
	}
	text := l.src[l.i : l.i+sign+j]
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return token{}, &SyntaxError{Pos: start, Msg: "number out of range", Near: text}
	}
	l.advance(sign + j)
	return token{kind: tNumber, text: text, num: f, pos: start, end: l.i}, nil
}
