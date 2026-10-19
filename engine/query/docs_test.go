package query

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBoxQLDocExamplesParse parses every command in the ```boxql blocks of the files in docs/: the
// documentation cannot drift from the parser. A block holds one or more commands; a command
// starts at a line that begins with "{" and runs until the next such line.
func TestBoxQLDocExamplesParse(t *testing.T) {
	docs, _ := filepath.Glob("../../docs/*.md")
	if len(docs) == 0 {
		t.Fatal("no docs found")
	}
	for _, doc := range docs {
		b, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		inBlock := false
		var cur []string
		flush := func() {
			if len(cur) == 0 {
				return
			}
			src := strings.Join(cur, "\n")
			cur = nil
			n++
			if _, _, err := Parse(src); err != nil {
				t.Errorf("%s: example does not parse: %v\n%s", doc, err, src)
			}
		}
		for _, line := range strings.Split(string(b), "\n") {
			switch {
			case strings.HasPrefix(line, "```boxql"):
				inBlock = true
			case inBlock && strings.HasPrefix(line, "```"):
				flush()
				inBlock = false
			case inBlock:
				if strings.TrimSpace(line) == "" {
					continue
				}
				if strings.HasPrefix(line, "<<") {
					continue
				}
				if strings.HasPrefix(line, "{") {
					flush()
				}
				cur = append(cur, line)
			}
		}
		if strings.HasSuffix(doc, "boxql.md") && n < 30 {
			t.Errorf("%s: only %d examples found", doc, n)
		}
	}
}
