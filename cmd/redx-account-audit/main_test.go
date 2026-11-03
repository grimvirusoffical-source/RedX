package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"reflect"
	"strings"
	"testing"
)

func checkpoint(body string) []byte {
	return []byte(body + fmt.Sprintf("<< REDX-CKPT v1 lsn=42 walgen=3 len=%d crc32c=%08x >>\n", len(body), crc32.Checksum([]byte(body), crc32.MakeTable(crc32.Castagnoli))))
}

func matching(t *testing.T, r map[string]any) []any {
	t.Helper()
	return r["matching_candidates"].([]any)
}

func TestInspectorFixtureAndJSONRecord(t *testing.T) {
	// Baseline private-value fixture from account-inspector-src/main_test.go.
	body := `{Record[ID=1]= [ {username[]} = "TestRedXAI", {emailVerified[]} = False, {passHash[]} = "SECRET_PASSWORD_HASH", {email[]} = "SECRET_EMAIL", {id[]} = "SECRET_ID", {emailOK[]} = "do not coerce", {activatedMs[]} = 1700000000000 ]};
{Record[ID=2]} = "SCALAR_SECRET";
{Record[ID=3]= [ {username[]} = "SomeoneElse", {emailVerified[]} = True, {otherSecret[]} = "HIDDEN_OTHER" ]};
{Record[ID=4]} = "{\"username\":\"TESTREDXAI\",\"email_verified\":true,\"emailOK\":false,\"activatedMs\":1700000000001,\"privateValue\":\"PRIVATE_VALUE\",\"SECRET_FIELD\\n\":\"PRIVATE\"}";
{Record[ID=5]} = "{\"nested\":{\"username\":\"TestRedXAI\"}}";
{Record[ID=6]} = "{\"username\":\"TestRedXAIsuffix\"}";
`
	data := checkpoint(body)
	before := append([]byte(nil), data...)
	r, err := inspect(data, "testredxai")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, before) {
		t.Fatal("input was changed")
	}
	if r["wal_replayed"] != false || r["checkpoint_valid"] != true || r["matching_candidate_count"] != 2 || r["readable_candidate_count"] != 5 {
		t.Fatal("wrong fixture counts", r)
	}
	if !reflect.DeepEqual(r["record_value_types"], map[string]int{"box": 2, "string": 4}) {
		t.Fatal("wrong type counts")
	}
	a := matching(t, r)[0].(map[string]any)
	if !reflect.DeepEqual(a["verification_boolean_values"], map[string]bool{"emailVerified": false}) {
		t.Fatal("coerced or lost boolean")
	}
	b := matching(t, r)[1].(map[string]any)
	if !reflect.DeepEqual(b["verification_boolean_values"], map[string]bool{"email_verified": true, "emailOK": false}) || b["suppressed_field_names"] != 1 {
		t.Fatal("JSON sanitization failed")
	}
	if !reflect.DeepEqual(a["activatedMs"], map[string]any{"present": true, "type": "number", "positive": true}) {
		t.Fatal("activation summary missing")
	}
	if !reflect.DeepEqual(b["field_names"], []string{"activatedMs", "emailOK", "email_verified", "privateValue", "username"}) {
		t.Fatal("field names unsorted or unsafe")
	}
	j, _ := json.Marshal(r)
	for _, secret := range []string{"SECRET_", "HIDDEN_OTHER", "PRIVATE_VALUE", "SomeoneElse", "TestRedXAI", "do not coerce", "1700000000000", "1700000000001"} {
		if strings.Contains(string(j), secret) {
			t.Fatal("private value leaked")
		}
	}
}

func TestActivationTypesAndNoCoercion(t *testing.T) {
	for _, tc := range []struct {
		value, kind string
		positive    bool
	}{{"", "absent", false}, {"null", "null", false}, {"true", "bool", false}, {`"1700000000000"`, "string", false}, {"-2", "number", false}, {"0", "number", false}, {"-0e99", "number", false}, {"2", "number", true}, {"1e-9999", "number", true}, {"1e9999", "number", true}, {"[]", "array", false}, {"{}", "object", false}} {
		t.Run(tc.kind+tc.value, func(t *testing.T) {
			m := map[string]json.RawMessage{"username": json.RawMessage(`"fixture"`), "emailVerified": json.RawMessage(`null`)}
			if tc.value != "" {
				m["activatedMs"] = json.RawMessage(tc.value)
			}
			j, _ := json.Marshal(m)
			quoted, _ := json.Marshal(string(j))
			r, e := inspect(checkpoint("{Record[ID=1]} = "+string(quoted)+";\n"), "FIXTURE")
			if e != nil {
				t.Fatal(e)
			}
			a := matching(t, r)[0].(map[string]any)
			if !reflect.DeepEqual(a["activatedMs"], map[string]any{"present": tc.value != "", "type": tc.kind, "positive": tc.positive}) || len(a["verification_boolean_values"].(map[string]bool)) != 0 {
				t.Fatal("unexpected status")
			}
		})
	}
}

func TestRejectInvalidAndKeepErrorsFixed(t *testing.T) {
	good := checkpoint("{Record[ID=1]} = True;\n")
	corrupt := append([]byte(nil), good...)
	corrupt[0] = '!'
	badLen := bytes.Replace(good, []byte("len="), []byte("len=9"), 1)
	for _, data := range [][]byte{[]byte("NO_FOOTER_SECRET"), corrupt, badLen, append(append([]byte(nil), good...), []byte("PRIVATE_TRAILER")...), checkpoint("SECRET_PARSER_PAYLOAD invalid ("), bytes.Repeat([]byte{'x'}, limit+1), bytes.Replace(good, []byte("lsn=42"), []byte("lsn=999999999999999999999999999"), 1)} {
		if _, e := inspect(data, "fixture"); e != invalid {
			t.Fatal("invalid checkpoint accepted or raw error exposed", e)
		}
	}
	if _, e := inspect(good, ""); e != invalid {
		t.Fatal("empty target accepted")
	}
}

func TestWalkNestedBoxesAndArrays(t *testing.T) {
	body := `{Container = [ {Records[]} = ;[ [ {Record} = "{\"username\":\"fixture\"}" ] ]: ]};`
	r, e := inspect(checkpoint(body), "fixture")
	if e != nil || r["matching_candidate_count"] != 1 {
		t.Fatal("nested record not found", e)
	}
}

func TestExactDirectEmailMatchingAndPrivacy(t *testing.T) {
	body := `{Record[ID=1]= [ {username[]} = "BoxOwner", {email[]} = "Fixture@Example.invalid", {emailVerified[]} = False, {privateBox[]} = "BOX_SECRET" ]};
{Record[ID=2]} = "{\"username\":\"JSONOwner\",\"EMAIL\":\"FIXTURE@EXAMPLE.INVALID\",\"emailOK\":true,\"privateJSON\":\"JSON_SECRET\"}";
{Record[ID=3]} = "{\"email\":\"wrong@example.invalid\",\"wrongOnlyField\":\"WRONG_SECRET\"}";
{Record[ID=4]} = "{\"nested\":{\"email\":\"fixture@example.invalid\"},\"nestedOnlyField\":true}";
{Record[ID=5]} = "{\"email\":\"prefixfixture@example.invalid\"}";
{Record[ID=6]} = "{\"email\":\"fixture@example.invalid.suffix\"}";
{Record[ID=7]} = "{\"email\":\"fixture+alias@example.invalid\"}";
{Record[ID=8]} = "{\"email\":\"fix.ture@example.invalid\"}";
`
	r, e := inspect(checkpoint(body), "fixture@example.invalid")
	if e != nil {
		t.Fatal(e)
	}
	if r["matching_candidate_count"] != 2 {
		t.Fatal("direct email match was not exact and case insensitive")
	}
	j, _ := json.Marshal(r)
	for _, private := range []string{"@", "BoxOwner", "JSONOwner", "SECRET", "wrongOnlyField", "nestedOnlyField"} {
		if strings.Contains(string(j), private) {
			t.Fatal("private email or unrelated record metadata leaked")
		}
	}
	r, e = inspect(checkpoint(body), "absent@example.invalid")
	if e != nil || r["matching_candidate_count"] != 0 {
		t.Fatal("wrong email matched")
	}
}

func TestNativeKeyedCandidatesAndNoDuplicateMatch(t *testing.T) {
	body := `{PRIVATE_NATIVE_KEY[ID=8123]} = "{\"username\":\"fixture\",\"email\":\"native@example.invalid\",\"activatedMs\":1700000000002,\"passwordHash\":\"PRIVATE_HASH\"}";
{PRIVATE_BOX_KEY[ID=9234]= [ {username[]} = "FIXTURE", {email[]} = "box@example.invalid", {emailVerified[]} = True, {activatedMs[]} = 1700000000003 ]};
{Record[ID=4567]} = "{\"username\":\"fixture\",\"email\":\"fixture\",\"emailOK\":false}";
{PRIVATE_WRONG_KEY} = "{\"username\":\"someone-else\",\"wrongOnlyField\":\"WRONG_SECRET\"}";
{PRIVATE_NESTED_KEY} = "{\"nested\":{\"username\":\"fixture\"},\"nestedOnlyField\":true}";
{PRIVATE_EMPTY_KEY} = "{}";
{PRIVATE_TRAILER_KEY} = "{\"username\":\"fixture\",\"trailerOnlyField\":true} {}";
{fixture} = "fixture";
{PRIVATE_NULL_KEY} = "null";
{PRIVATE_ARRAY_KEY} = "[]";
`
	r, e := inspect(checkpoint(body), "Fixture")
	if e != nil {
		t.Fatal(e)
	}
	if r["matching_candidate_count"] != 3 || r["readable_candidate_count"] != 6 || r["walked_entry_count"] != 14 || r["wal_replayed"] != false {
		t.Fatal("candidate counts incorrect or candidate matched twice", r)
	}
	if !reflect.DeepEqual(r["record_value_types"], map[string]int{"string": 1}) || !reflect.DeepEqual(r["candidate_value_types"], map[string]int{"string": 5, "box": 1}) {
		t.Fatal("candidate/Record counts conflated")
	}
	j, _ := json.Marshal(r)
	for _, private := range []string{"PRIVATE_", "8123", "9234", "4567", "@", "someone-else", "WRONG_SECRET", "wrongOnlyField", "nestedOnlyField", "trailerOnlyField", "1700000000002", "1700000000003"} {
		if strings.Contains(string(j), private) {
			t.Fatal("native entry key, ID or value leaked")
		}
	}
	r, e = inspect(checkpoint(body), "NATIVE@EXAMPLE.INVALID")
	if e != nil || r["matching_candidate_count"] != 1 {
		t.Fatal("native JSON email did not match exactly")
	}
}
