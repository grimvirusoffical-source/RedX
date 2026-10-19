package redx

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// BoxTextError is a Box text the decoder does not understand.
type BoxTextError struct {
	Msg    string
	Offset int
}

func (e *BoxTextError) Error() string {
	return fmt.Sprintf("box text: %s (at offset %d)", e.Msg, e.Offset)
}

// FromBox decodes the Box text of one value with the host's JSON mapping (docs/box-grammar.md):
// string, number (float64), TRUE/FALSE, NELL (nil), ;[a, b]: ([]any), [ {K[]} = v, {K[ID=2]} = w ]
// (map[string]any with keys "K" and "K[ID=2]") and links ({"$link": "<text>"}). TTL markers are skipped.
func FromBox(text string) (v any, err error) {
	r := &boxReader{s: text}
	defer func() {
		if p := recover(); p != nil {
			if be, ok := p.(*BoxTextError); ok {
				v, err = nil, be
				return
			}
			panic(p)
		}
	}()
	v = r.value(0)
	r.ttl()
	if r.peek() != 0 {
		r.fail("unexpected text after the value")
	}
	return v, nil
}

type boxReader struct {
	s string
	i int
}

func (r *boxReader) fail(msg string) { panic(&BoxTextError{msg, r.i}) }

func (r *boxReader) at(i int) byte {
	if i < len(r.s) {
		return r.s[i]
	}
	return 0
}

func (r *boxReader) ws() {
	for {
		c := r.at(r.i)
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			r.i++
		case c == '<' && r.at(r.i+1) == '<':
			end := strings.Index(r.s[r.i+2:], ">>")
			if end < 0 {
				r.fail("unterminated comment")
			}
			r.i += 2 + end + 2
		default:
			return
		}
	}
}

func (r *boxReader) peek() byte { r.ws(); return r.at(r.i) }
func (r *boxReader) eat(c byte) bool {
	if r.peek() == c {
		r.i++
		return true
	}
	return false
}
func (r *boxReader) expect(c byte) {
	if !r.eat(c) {
		r.fail(fmt.Sprintf("expected '%c'", c))
	}
}

func identStart(c byte) bool { return c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z') || c >= 0x80 }
func identPart(c byte) bool  { return identStart(c) || (c >= '0' && c <= '9') || c == '-' }

func (r *boxReader) str() string {
	start := r.i
	if r.at(r.i) != '"' {
		r.fail("expected a string")
	}
	r.i++
	for {
		c := r.at(r.i)
		if r.i >= len(r.s) {
			r.fail("unterminated string")
		}
		if c == '\\' {
			r.i += 2
			continue
		}
		r.i++
		if c == '"' {
			break
		}
	}
	var out string
	if err := json.Unmarshal([]byte(r.s[start:r.i]), &out); err != nil {
		r.i = start
		r.fail("bad string literal")
	}
	return out
}

var numRe = regexp.MustCompile(`^-?\d+(\.\d+)?([eE][+-]?\d+)?`)

func (r *boxReader) number() float64 {
	m := numRe.FindString(r.s[r.i:])
	if m == "" {
		r.fail("expected a number")
	}
	r.i += len(m)
	f, _ := strconv.ParseFloat(m, 64)
	return f
}

func (r *boxReader) ident() string {
	st := r.i
	if !identStart(r.at(r.i)) {
		r.fail("expected an identifier")
	}
	for r.i < len(r.s) && identPart(r.s[r.i]) {
		r.i++
	}
	return r.s[st:r.i]
}

var ttlRe = regexp.MustCompile(`^\(\s*~?\d+(@\d+)?\s*$`)

func (r *boxReader) ttl() {
	if r.peek() != '(' {
		return
	}
	end := strings.IndexByte(r.s[r.i:], ')')
	if end < 0 || !ttlRe.MatchString(r.s[r.i:r.i+end]) {
		r.fail("bad TTL marker")
	}
	r.i += end + 1
	if r.at(r.i) == '*' {
		r.i++
	}
}

func (r *boxReader) linkText(start int) string {
	depth := 0
	r.i = start
	for r.i < len(r.s) {
		c := r.s[r.i]
		if c == '"' {
			r.str()
			continue
		}
		if c == '[' {
			depth++
		} else if c == ']' || c == '}' {
			if depth == 0 {
				break
			}
			depth--
		} else if (c == ',' || c == ';') && depth == 0 {
			break
		}
		r.i++
	}
	return strings.TrimSpace(r.s[start:r.i])
}

func (r *boxReader) value(depth int) any {
	if depth > 200 {
		r.fail("nested too deeply")
	}
	c := r.peek()
	switch {
	case r.i >= len(r.s):
		r.fail("unexpected end of input")
	case c == '"':
		start := r.i
		s := r.str()
		j := r.i
		for j < len(r.s) && strings.ContainsRune(" \t\r\n", rune(r.s[j])) {
			j++
		}
		if r.at(j) == ':' && identStart(r.at(j+1)) {
			return map[string]any{"$link": r.linkText(start)}
		}
		return s
	case c == ';':
		r.i++
		r.expect('[')
		arr := []any{}
		if !r.eat(']') {
			for {
				arr = append(arr, r.value(depth+1))
				if !r.eat(',') {
					break
				}
			}
			r.expect(']')
		}
		r.expect(':')
		return arr
	case c == '[':
		r.i++
		return r.boxBody(depth + 1)
	case c == '-' || (c >= '0' && c <= '9'):
		return r.number()
	case identStart(c):
		w := strings.ToUpper(r.ident())
		switch w {
		case "TRUE":
			return true
		case "FALSE":
			return false
		case "NELL":
			return nil
		}
		r.fail("unexpected word " + w)
	}
	r.fail("unexpected character")
	return nil
}

var idAttr = regexp.MustCompile(`^(?i:ID\s*=\s*)?(-?\d+)\s*[,\]]`)

func (r *boxReader) boxBody(depth int) map[string]any {
	out := map[string]any{}
	for !r.eat(']') {
		r.expect('{')
		name := r.ident()
		id := ""
		if r.eat('[') {
			for !r.eat(']') {
				r.ws()
				if m := idAttr.FindStringSubmatch(r.s[r.i:]); m != nil && id == "" {
					id = m[1]
					r.i += len(m[0]) - 1 // leave the ',' or ']'
				} else {
					for r.i < len(r.s) && r.s[r.i] != ',' && r.s[r.i] != ']' {
						if r.s[r.i] == '"' {
							r.str()
						} else {
							r.i++
						}
					}
				}
				r.eat(',')
			}
		}
		r.expect('}')
		r.expect('=')
		v := r.value(depth + 1)
		r.ttl()
		if id != "" {
			name = name + "[ID=" + id + "]"
		}
		out[name] = v
		if !r.eat(',') {
			r.eat(';')
		}
	}
	return out
}
