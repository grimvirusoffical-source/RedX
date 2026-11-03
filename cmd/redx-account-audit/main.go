// Metadata only: protected checkpoint COPY, no WAL replay or schema/auth proof.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"redx/box"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const limit = 64 << 20

var invalid = errors.New("invalid checkpoint or target")
var footer = regexp.MustCompile(`^<< REDX-CKPT v1 lsn=([0-9]+) walgen=([0-9]+) len=([0-9]+) crc32c=([0-9a-fA-F]{8}) >>\n?$`)
var safe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

func inspect(data []byte, target string) (map[string]any, error) {
	i := bytes.LastIndex(data, []byte("<< REDX-CKPT v1 "))
	if len(data) > limit || target == "" || len(target) > 256 || i < 0 {
		return nil, invalid
	}
	f := footer.FindSubmatch(data[i:])
	if f == nil {
		return nil, invalid
	}
	n := make([]uint64, 4)
	for j := range n {
		base := 10
		if j == 3 {
			base = 16
		}
		var err error
		n[j], err = strconv.ParseUint(string(f[j+1]), base, 64)
		if err != nil {
			return nil, invalid
		}
	}
	if n[2] != uint64(i) || n[3] > 0xffffffff || crc32.Checksum(data[:i], crc32.MakeTable(crc32.Castagnoli)) != uint32(n[3]) {
		return nil, invalid
	}
	root, err := box.ParseDocument(string(data[:i]))
	if err != nil {
		return nil, invalid
	}
	types := map[string]int{}
	candidateTypes := map[string]int{}
	matches := []any{}
	readable, entries := 0, 0
	var walk func(box.Value)
	walk = func(v box.Value) {
		if v.Kind == box.KindArray {
			for _, x := range v.Arr {
				walk(x)
			}
		}
		if v.Kind != box.KindBox || v.Box == nil {
			return
		}
		for _, e := range v.Box.Entries() {
			entries++
			if e.Key == "Record" {
				types[e.Value.Kind.String()]++
			}
			var raw []byte
			if e.Value.Kind == box.KindString {
				raw = []byte(e.Value.Str)
			} else if e.Value.Kind == box.KindBox && directLoginBox(e.Value.Box) {
				raw, _ = e.Value.MarshalJSON()
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) == nil && fields != nil {
				readable++
				candidateTypes[e.Value.Kind.String()]++
				found := false
				for k, v := range fields {
					var s string
					if (strings.EqualFold(k, "username") || strings.EqualFold(k, "email")) && json.Unmarshal(v, &s) == nil && strings.EqualFold(s, target) {
						found = true
					}
				}
				if found {
					names := []string{}
					flags := map[string]bool{}
					hidden := 0
					for k, v := range fields {
						if safe.MatchString(k) {
							names = append(names, k)
						} else {
							hidden++
						}
						if k == "emailVerified" || k == "email_verified" || k == "emailOK" {
							var b *bool
							if json.Unmarshal(v, &b) == nil && b != nil {
								flags[k] = *b
							}
						}
					}
					sort.Strings(names)
					v, present := fields["activatedMs"]
					kind := "absent"
					positive := false
					if present {
						var x any
						d := json.NewDecoder(bytes.NewReader(v))
						d.UseNumber()
						d.Decode(&x)
						switch t := x.(type) {
						case nil:
							kind = "null"
						case bool:
							kind = "bool"
						case string:
							kind = "string"
						case []any:
							kind = "array"
						case map[string]any:
							kind = "object"
						case json.Number:
							kind = "number"
							num := strings.SplitN(strings.ToLower(string(t)), "e", 2)[0]
							positive = !strings.HasPrefix(num, "-") && strings.ContainsAny(num, "123456789")
						}
					}
					matches = append(matches, map[string]any{"field_names": names, "suppressed_field_names": hidden, "verification_boolean_values": flags, "activatedMs": map[string]any{"present": present, "type": kind, "positive": positive}})
				}
			}
			walk(e.Value)
		}
	}
	walk(box.BoxValue(root))
	return map[string]any{"checkpoint_valid": true, "wal_replayed": false, "walked_entry_count": entries, "record_value_types": types, "candidate_value_types": candidateTypes, "readable_candidate_count": readable, "matching_candidate_count": len(matches), "matching_candidates": matches}, nil
}

func directLoginBox(b *box.Box) bool {
	for _, e := range b.Entries() {
		_, hasID := e.ID()
		if !hasID && e.Value.Kind == box.KindString && (strings.EqualFold(e.Key, "username") || strings.EqualFold(e.Key, "email")) {
			return true
		}
	}
	return false
}

func main() {
	if len(os.Args) != 3 {
		fail()
	}
	f, e := os.Open(os.Args[1])
	if e != nil {
		fail()
	}
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > limit {
		f.Close()
		fail()
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	f.Close()
	if e != nil {
		fail()
	}
	r, e := inspect(b, os.Args[2])
	if e != nil {
		fail()
	}
	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		fail()
	}
}
func fail() { os.Stderr.WriteString("checkpoint audit failed\n"); os.Exit(1) }
