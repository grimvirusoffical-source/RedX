package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestQuoteRoundTrip(t *testing.T) {
	samples := []string{
		`<>&\"`,
		"ed25519:<base64>",
		"café — 日本語",
		"emoji 😀",
		"quotes \" and ' and \\ slash",
		"line\nbreak\r\nand\ttab",
		"<tag>&amp;</tag>",
		"controls\x00\x01\x1f\x7f",
	}
	kinds := []struct {
		name  string
		quote func(string) string
		undo  func(string) (string, error)
	}{
		{"go", quoteGo, strconv.Unquote},
		{"js", quoteJS, unquoteJS},
		{"python", quotePy, unquotePy},
		{"swift", quoteSwift, unquoteSwift},
		{"csharp", quoteCS, unquoteCS},
		{"c", quoteC, unquoteC},
	}
	for _, k := range kinds {
		for _, s := range samples {
			lit := k.quote(s)
			if strings.Contains(lit, `\u003c`) || strings.Contains(lit, `\u003e`) || strings.Contains(lit, `\u0026`) {
				t.Errorf("%s quoted %q with a JSON HTML escape: %s", k.name, s, lit)
			}
			got, err := k.undo(lit)
			if err != nil {
				t.Errorf("%s unquote %q (%q): %v", k.name, s, lit, err)
				continue
			}
			if got != s {
				t.Errorf("%s round-trip %q -> %s -> %q", k.name, s, lit, got)
			}
		}
	}
	if _, err := unquoteSwift(`"\u003c"`); err == nil {
		t.Fatal(`Swift accepted \u003c, which is not a Swift escape`)
	}
}

func TestGeneratedLiteralsMatchSummary(t *testing.T) {
	summary := `<>&\" café — <base64>`
	s := &Spec{
		Auth:   map[string]string{"none": "no key"},
		Danger: []Danger{{Name: "safe", Level: 0, Meaning: `reads <only> & "x"`}},
	}
	s.ParamEncoding.Segments = []string{"file"}
	s.Operations = []Op{{
		ID: "health", Group: "host", Method: "GET", Path: "/healthz",
		Auth: "none", Danger: "safe", Summary: summary, Response: "json",
	}}
	checks := []struct {
		name string
		src  string
		lit  string
		undo func(string) (string, error)
	}{
		{"go", goOps(s), quoteGo(summary), strconv.Unquote},
		{"js", jsOps(s), quoteJS(summary), unquoteJS},
		{"python", pyOps(s), quotePy(summary), unquotePy},
		{"swift", swiftOps(s), quoteSwift(summary), unquoteSwift},
		{"csharp", csOps(s), quoteCS(summary), unquoteCS},
	}
	for _, c := range checks {
		if !strings.Contains(c.src, c.lit) {
			t.Errorf("%s output does not contain %s", c.name, c.lit)
		}
		if strings.Contains(c.src, `\u003c`) || strings.Contains(c.src, `\u003e`) || strings.Contains(c.src, `\u0026`) {
			t.Errorf("%s output still has a JSON HTML escape", c.name)
		}
		got, err := c.undo(c.lit)
		if err != nil || got != summary {
			t.Errorf("%s summary literal %s -> %q (%v)", c.name, c.lit, got, err)
		}
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "operations_gen.go", goOps(s), parser.AllErrors); err != nil {
		t.Fatalf("generated Go does not parse: %v", err)
	}
	for _, lit := range swiftStrings(t, swiftOps(s)) {
		if _, err := unquoteSwift(lit); err != nil {
			t.Errorf("swift literal %s: %v", lit, err)
		}
	}
	compileQuoted(t, summary)
}

func TestRealSpecStringLiterals(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "api", "redx-api.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s Spec
	if err := jsonUnmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	goSrc := goOps(&s)
	jsSrc := jsOps(&s)
	pySrc := pyOps(&s)
	sw := swiftOps(&s)
	csSrc := csOps(&s)
	if strings.Contains(sw, `\u003`) || strings.Contains(sw, `\u0026`) {
		t.Fatal("real Swift SDK still contains a JSON HTML escape")
	}
	for _, lit := range swiftStrings(t, sw) {
		if _, err := unquoteSwift(lit); err != nil {
			t.Errorf("real swift literal %s: %v", lit, err)
		}
	}
	for _, o := range s.Operations {
		if !strings.Contains(sw, "summary: "+quoteSwift(o.Summary)) {
			t.Errorf("swift missing summary %q", o.Summary)
		}
		if !strings.Contains(goSrc, "Summary: "+quoteGo(o.Summary)) {
			t.Errorf("go missing summary %q", o.Summary)
		}
		if !strings.Contains(jsSrc, "summary: "+quoteJS(o.Summary)) {
			t.Errorf("js missing summary %q", o.Summary)
		}
		if !strings.Contains(pySrc, `"summary": `+quotePy(o.Summary)) {
			t.Errorf("python missing summary %q", o.Summary)
		}
		if !strings.Contains(csSrc, "Summary = "+quoteCS(o.Summary)) {
			t.Errorf("csharp missing summary %q", o.Summary)
		}
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "operations_gen.go", goSrc, parser.AllErrors); err != nil {
		t.Fatal(err)
	}
	compileQuoted(t, `<>&\"`)
}

func jsonUnmarshal(b []byte, s *Spec) error {
	return json.Unmarshal(b, s)
}

func swiftStrings(t *testing.T, src string) []string {
	t.Helper()
	var out []string
	for i := 0; i < len(src); {
		if strings.HasPrefix(src[i:], "//") {
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				break
			}
			i += j + 1
			continue
		}
		if src[i] != '"' {
			i++
			continue
		}
		lit, n, err := takeQuoted(src[i:], unquoteSwift)
		if err != nil {
			t.Fatalf("swift string at %d: %v\n%s", i, err, src[i:min(i+40, len(src))])
		}
		out = append(out, lit)
		i += n
	}
	return out
}

func takeQuoted(src string, undo func(string) (string, error)) (string, int, error) {
	if len(src) < 2 || src[0] != '"' {
		return "", 0, fmt.Errorf("not a string")
	}
	for i := 1; i < len(src); i++ {
		if src[i] == '\\' {
			i++
			continue
		}
		if src[i] == '"' {
			lit := src[:i+1]
			if _, err := undo(lit); err != nil {
				return "", 0, err
			}
			return lit, i + 1, nil
		}
	}
	return "", 0, fmt.Errorf("unterminated string")
}

func compileQuoted(t *testing.T, summary string) {
	t.Helper()
	if _, err := exec.LookPath("go"); err == nil {
		dir := t.TempDir()
		path := filepath.Join(dir, "main.go")
		src := "package main\nimport \"os\"\nfunc main() { os.Stdout.WriteString(" + quoteGo(summary) + ") }\n"
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := exec.Command("go", "run", path).Output()
		if err != nil {
			t.Errorf("go run: %v", err)
		} else if !bytes.Equal(got, []byte(summary)) {
			t.Errorf("go printed %q want %q", got, summary)
		}
	}
	if _, err := exec.LookPath("node"); err == nil {
		dir := t.TempDir()
		path := filepath.Join(dir, "p.js")
		prog := "process.stdout.write(" + quoteJS(summary) + ")\n"
		if err := os.WriteFile(path, []byte(prog), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := exec.Command("node", path).Output()
		if err != nil {
			t.Errorf("node: %v", err)
		} else if !bytes.Equal(got, []byte(summary)) {
			t.Errorf("node printed %q", got)
		}
	} else {
		t.Log("skip node compile: node not installed")
	}
	py := "python3"
	if _, err := exec.LookPath(py); err != nil {
		py = "python"
	}
	if _, err := exec.LookPath(py); err == nil {
		prog := "import sys\nsys.stdout.buffer.write((" + quotePy(summary) + ").encode('utf-8'))\n"
		cmd := exec.Command(py, "-c", prog)
		got, err := cmd.Output()
		if err != nil {
			t.Errorf("python: %v", err)
		} else if !bytes.Equal(got, []byte(summary)) {
			t.Errorf("python printed %q", got)
		}
	} else {
		t.Log("skip python compile: python not installed")
	}
	if _, err := exec.LookPath("swiftc"); err == nil {
		dir := t.TempDir()
		path := filepath.Join(dir, "p.swift")
		src := "let s = " + quoteSwift(summary) + "\nprint(s, terminator: \"\")\n"
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(dir, "prog")
		if out, err := exec.Command("swiftc", "-o", bin, path).CombinedOutput(); err != nil {
			t.Errorf("swiftc: %v\n%s", err, out)
		} else if got, err := exec.Command(bin).Output(); err != nil {
			t.Errorf("swift run: %v", err)
		} else if !bytes.Equal(got, []byte(summary)) {
			t.Errorf("swift printed %q want %q", got, summary)
		}
	} else {
		t.Log("skip swiftc: not installed")
	}
	cc := ""
	for _, name := range []string{"gcc", "cc", "clang"} {
		if _, err := exec.LookPath(name); err == nil {
			cc = name
			break
		}
	}
	if cc != "" {
		dir := t.TempDir()
		path := filepath.Join(dir, "p.c")
		src := "#include <stdio.h>\n#include <string.h>\nint main(void){const char *s=" + quoteC(summary) + ";fwrite(s,1,strlen(s),stdout);return 0;}\n"
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(dir, "prog")
		if out, err := exec.Command(cc, "-o", bin, path).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", cc, err, out)
		} else if got, err := exec.Command(bin).Output(); err != nil {
			t.Errorf("c run: %v", err)
		} else if !bytes.Equal(got, []byte(summary)) {
			t.Errorf("c printed %q want %q", got, summary)
		}
	} else {
		t.Log("skip C compile: no compiler")
	}
	for _, csc := range []string{"csc", "mcs"} {
		if _, err := exec.LookPath(csc); err != nil {
			continue
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "p.cs")
		src := "using System;\nclass P{static void Main(){var s=" + quoteCS(summary) + ";var b=System.Text.Encoding.UTF8.GetBytes(s);Console.OpenStandardOutput().Write(b,0,b.Length);}}\n"
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		exe := filepath.Join(dir, "prog.exe")
		if out, err := exec.Command(csc, "-nologo", "-out:"+exe, path).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", csc, err, out)
			break
		}
		got, err := exec.Command(exe).Output()
		if err != nil {
			t.Errorf("csharp run: %v", err)
		} else if !bytes.Equal(got, []byte(summary)) {
			t.Errorf("csharp printed %q want %q", got, summary)
		}
		break
	}
}

func unquoteJS(lit string) (string, error) {
	return unquoteSlash(lit, func(s string, i int) (rune, int, error) {
		if i >= len(s) {
			return 0, 0, fmt.Errorf("truncated escape")
		}
		switch s[i] {
		case '\\', '"', '\'', '/':
			return rune(s[i]), 1, nil
		case 'n':
			return '\n', 1, nil
		case 'r':
			return '\r', 1, nil
		case 't':
			return '\t', 1, nil
		case 'b':
			return '\b', 1, nil
		case 'f':
			return '\f', 1, nil
		case 'v':
			return '\v', 1, nil
		case 'u':
			if i+5 > len(s) {
				return 0, 0, fmt.Errorf("short \\u")
			}
			v, err := strconv.ParseUint(s[i+1:i+5], 16, 16)
			if err != nil {
				return 0, 0, err
			}
			return rune(v), 5, nil
		case 'x':
			if i+3 > len(s) {
				return 0, 0, fmt.Errorf("short \\x")
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return 0, 0, err
			}
			return rune(v), 3, nil
		default:
			return 0, 0, fmt.Errorf("bad js escape \\%c", s[i])
		}
	})
}

func unquotePy(lit string) (string, error) {
	return unquoteSlash(lit, func(s string, i int) (rune, int, error) {
		if i >= len(s) {
			return 0, 0, fmt.Errorf("truncated escape")
		}
		switch s[i] {
		case '\\', '"', '\'':
			return rune(s[i]), 1, nil
		case 'n':
			return '\n', 1, nil
		case 'r':
			return '\r', 1, nil
		case 't':
			return '\t', 1, nil
		case 'a':
			return '\a', 1, nil
		case 'b':
			return '\b', 1, nil
		case 'f':
			return '\f', 1, nil
		case 'v':
			return '\v', 1, nil
		case 'u':
			if i+5 > len(s) {
				return 0, 0, fmt.Errorf("short \\u")
			}
			v, err := strconv.ParseUint(s[i+1:i+5], 16, 16)
			if err != nil {
				return 0, 0, err
			}
			return rune(v), 5, nil
		case 'U':
			if i+9 > len(s) {
				return 0, 0, fmt.Errorf("short \\U")
			}
			v, err := strconv.ParseUint(s[i+1:i+9], 16, 32)
			if err != nil || !utf8.ValidRune(rune(v)) {
				return 0, 0, fmt.Errorf("bad \\U")
			}
			return rune(v), 9, nil
		default:
			return 0, 0, fmt.Errorf("bad python escape \\%c", s[i])
		}
	})
}

func unquoteSwift(lit string) (string, error) {
	return unquoteSlash(lit, func(s string, i int) (rune, int, error) {
		if i >= len(s) {
			return 0, 0, fmt.Errorf("truncated escape")
		}
		switch s[i] {
		case '\\', '"', '\'':
			return rune(s[i]), 1, nil
		case 'n':
			return '\n', 1, nil
		case 'r':
			return '\r', 1, nil
		case 't':
			return '\t', 1, nil
		case '0':
			return 0, 1, nil
		case 'u':
			if i+1 >= len(s) || s[i+1] != '{' {
				return 0, 0, fmt.Errorf("swift unicode escape must be \\u{...}")
			}
			end := strings.IndexByte(s[i+2:], '}')
			if end <= 0 || end > 8 {
				return 0, 0, fmt.Errorf("bad swift unicode")
			}
			v, err := strconv.ParseUint(s[i+2:i+2+end], 16, 32)
			if err != nil || !utf8.ValidRune(rune(v)) {
				return 0, 0, fmt.Errorf("bad swift unicode")
			}
			return rune(v), 2 + end + 1, nil
		default:
			return 0, 0, fmt.Errorf("bad swift escape \\%c", s[i])
		}
	})
}

func unquoteCS(lit string) (string, error) {
	return unquoteSlash(lit, func(s string, i int) (rune, int, error) {
		if i >= len(s) {
			return 0, 0, fmt.Errorf("truncated escape")
		}
		switch s[i] {
		case '\\', '"', '\'':
			return rune(s[i]), 1, nil
		case 'n':
			return '\n', 1, nil
		case 'r':
			return '\r', 1, nil
		case 't':
			return '\t', 1, nil
		case '0':
			return 0, 1, nil
		case 'a':
			return '\a', 1, nil
		case 'b':
			return '\b', 1, nil
		case 'f':
			return '\f', 1, nil
		case 'v':
			return '\v', 1, nil
		case 'u':
			if i+5 > len(s) {
				return 0, 0, fmt.Errorf("short \\u")
			}
			v, err := strconv.ParseUint(s[i+1:i+5], 16, 16)
			if err != nil {
				return 0, 0, err
			}
			return rune(v), 5, nil
		case 'U':
			if i+9 > len(s) {
				return 0, 0, fmt.Errorf("short \\U")
			}
			v, err := strconv.ParseUint(s[i+1:i+9], 16, 32)
			if err != nil || !utf8.ValidRune(rune(v)) {
				return 0, 0, fmt.Errorf("bad \\U")
			}
			return rune(v), 9, nil
		default:
			return 0, 0, fmt.Errorf("bad csharp escape \\%c", s[i])
		}
	})
}

func unquoteC(lit string) (string, error) {
	if len(lit) < 2 || lit[0] != '"' || lit[len(lit)-1] != '"' {
		return "", fmt.Errorf("not quoted")
	}
	s := lit[1 : len(lit)-1]
	var buf []byte
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			buf = append(buf, s[i])
			i++
			continue
		}
		if i+1 >= len(s) {
			return "", fmt.Errorf("truncated escape")
		}
		switch s[i+1] {
		case '\\', '"', '\'':
			buf = append(buf, s[i+1])
			i += 2
		case 'n':
			buf = append(buf, '\n')
			i += 2
		case 'r':
			buf = append(buf, '\r')
			i += 2
		case 't':
			buf = append(buf, '\t')
			i += 2
		case 'a':
			buf = append(buf, '\a')
			i += 2
		case 'b':
			buf = append(buf, '\b')
			i += 2
		case 'f':
			buf = append(buf, '\f')
			i += 2
		case 'v':
			buf = append(buf, '\v')
			i += 2
		case 'u':
			if i+6 > len(s) {
				return "", fmt.Errorf("short \\u")
			}
			v, err := strconv.ParseUint(s[i+2:i+6], 16, 16)
			if err != nil || v < 0xA0 {
				return "", fmt.Errorf("bad C universal character")
			}
			var tmp [utf8.UTFMax]byte
			n := utf8.EncodeRune(tmp[:], rune(v))
			buf = append(buf, tmp[:n]...)
			i += 6
		case 'U':
			if i+10 > len(s) {
				return "", fmt.Errorf("short \\U")
			}
			v, err := strconv.ParseUint(s[i+2:i+10], 16, 32)
			if err != nil || !utf8.ValidRune(rune(v)) || v < 0xA0 {
				return "", fmt.Errorf("bad C universal character")
			}
			var tmp [utf8.UTFMax]byte
			n := utf8.EncodeRune(tmp[:], rune(v))
			buf = append(buf, tmp[:n]...)
			i += 10
		default:
			if s[i+1] < '0' || s[i+1] > '7' {
				return "", fmt.Errorf("bad C escape \\%c", s[i+1])
			}
			j := i + 1
			n := 0
			val := 0
			for n < 3 && j < len(s) && s[j] >= '0' && s[j] <= '7' {
				val = val*8 + int(s[j]-'0')
				j++
				n++
			}
			buf = append(buf, byte(val))
			i = j
		}
	}
	if !utf8.Valid(buf) {
		return "", fmt.Errorf("invalid utf-8")
	}
	return string(buf), nil
}

func unquoteSlash(lit string, esc func(string, int) (rune, int, error)) (string, error) {
	if len(lit) < 2 || lit[0] != '"' || lit[len(lit)-1] != '"' {
		return "", fmt.Errorf("not quoted")
	}
	s := lit[1 : len(lit)-1]
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				return "", fmt.Errorf("bad utf-8")
			}
			b.WriteRune(r)
			i += size
			continue
		}
		r, n, err := esc(s, i+1)
		if err != nil {
			return "", err
		}
		b.WriteRune(r)
		i += 1 + n
	}
	return b.String(), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
