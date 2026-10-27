//go:build qa

package host_test

// Independent QA harness for the rxa-lifetime-cert owner-only freeze.
// Retest head c1c4be9d19ec7c226257c865de931c335c06d1f8. Product sources are
// not modified. Field material is recorded only as present or absent. The
// canary is a marker, not a key, and is never logged.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"redx/host"
	"redx/host/engineadapter"
)

const qaMarker = "QA-CANARY-PRIVATE-ENC"

const (
	qaPub    = "pk-qa-public-half"
	qaCert   = "cert-qa-id"
	qaMail   = "owner-emails-qa@example.com"
	qaIssued = "issued-qa-stamp"
	qaSig    = "sig-qa-prefix"
)

type qaHit struct {
	secret, pub, cert, mail, issued, sig bool
}

func scanQA(s string) qaHit {
	return qaHit{
		secret: strings.Contains(s, qaMarker),
		pub:    strings.Contains(s, qaPub),
		cert:   strings.Contains(s, qaCert),
		mail:   strings.Contains(s, qaMail),
		issued: strings.Contains(s, qaIssued),
		sig:    strings.Contains(s, qaSig),
	}
}

func (h qaHit) any() bool { return h.secret || h.pub || h.cert || h.mail || h.issued || h.sig }

func (h qaHit) String() string {
	yn := func(b bool) string {
		if b {
			return "present"
		}
		return "absent"
	}
	return fmt.Sprintf("secret=%s pubkey=%s cert_id=%s owner_emails=%s issued=%s sig=%s",
		yn(h.secret), yn(h.pub), yn(h.cert), yn(h.mail), yn(h.issued), yn(h.sig))
}

type qaStats struct {
	mu                    sync.Mutex
	class                 map[string]int
	leakSecret, leakClean int
	pemBanners            int
}

func (s *qaStats) note(class string, secret bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.class == nil {
		s.class = map[string]int{}
	}
	s.class[class]++
	if class == "LEAK" {
		if secret {
			s.leakSecret++
		} else {
			s.leakClean++
		}
	}
}

func (s *qaStats) addPEM(n int) {
	if s == nil || n == 0 {
		return
	}
	s.mu.Lock()
	s.pemBanners += n
	s.mu.Unlock()
}

func (s *qaStats) line() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	order := []string{"LEAK", "CLOSED", "QUIET", "CLEAR", "CONTROL-OK", "CONTROL-FAIL", "OWNER-OK", "OWNER-FAIL", "OPEN", "ODD", "UPGRADED", "STATUS"}
	seen := map[string]bool{}
	var b strings.Builder
	for _, k := range order {
		seen[k] = true
		fmt.Fprintf(&b, "%s=%d ", k, s.class[k])
	}
	extra := make([]string, 0)
	for k := range s.class {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sortStrings(extra)
	for _, k := range extra {
		fmt.Fprintf(&b, "%s=%d ", k, s.class[k])
	}
	fmt.Fprintf(&b, "leak_ciphertext_present=%d leak_ciphertext_absent=%d pem_banners=%d", s.leakSecret, s.leakClean, s.pemBanners)
	return b.String()
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		j := i
		for j > 0 && a[j] < a[j-1] {
			a[j], a[j-1] = a[j-1], a[j]
			j--
		}
	}
}

type qaServer struct {
	*node
	logs  []string
	mu    sync.Mutex
	stats *qaStats
}

func startRealQA(t *testing.T, mod func(*host.Config)) *qaServer {
	t.Helper()
	n := &node{Dir: t.TempDir()}
	n.Srv = httptest.NewUnstartedServer(nil)
	n.URL = "http://" + n.Srv.Listener.Addr().String()
	cfg := baseCfg(n.Dir)
	cfg.Advertise = n.URL
	cfg.ClusterKey = "qa-review-cluster-key"
	// The review issues hundreds of reads on one key. The default burst is
	// 200, which turns later probes into 429s. The limiter is not the gate
	// under test.
	cfg.RateRPS = 1e6
	cfg.RateBurst = 1000000
	if mod != nil {
		mod(&cfg)
	}
	qs := &qaServer{node: n}
	h, err := host.New(cfg, engineadapter.Opener(engineadapter.Config{
		SweepMS:          50,
		CodeAllowedBoxes: []string{"*"},
	}), func(f string, a ...interface{}) {
		msg := fmt.Sprintf(f, a...)
		qs.mu.Lock()
		qs.logs = append(qs.logs, msg)
		qs.mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	n.H = h
	n.Key = h.BootstrapKey
	n.Srv.Config.Handler = h.Handler()
	n.Srv.Start()
	t.Cleanup(n.Stop)
	return qs
}

func certBox() string {
	return `[ {cert_id[]} = "` + qaCert + `", {pubkey[]} = "` + qaPub + `", {private_enc[]} = "` + qaMarker + `", {issued[]} = "` + qaIssued + `", {owner_emails[]} = ;["` + qaMail + `"]:, {sig_id_prefix[]} = "` + qaSig + `" ]`
}

type qaProbe struct {
	name, method, rawURL, key, body, mode string
	hdr                                   []string
}

func (q *qaServer) probe(t *testing.T, p qaProbe) (int, qaHit) {
	t.Helper()
	st, body, _ := do(t, p.method, p.rawURL, p.key, p.body, p.hdr...)
	hit := scanQA(body)
	class := "CLEAR"
	fail := false
	switch p.mode {
	case "must403":
		if hit.any() {
			class, fail = "LEAK", true
		} else if st != 403 {
			class, fail = "OPEN", true
		} else {
			class = "CLOSED"
		}
	case "hunt":
		if hit.any() {
			class, fail = "LEAK", true
		} else if st == 403 {
			class = "CLOSED"
		} else if st == 200 {
			class = "CLEAR"
		} else {
			class, fail = "ODD", true
		}
	case "spot":
		if hit.any() {
			class, fail = "LEAK", true
		} else if st == 403 {
			class = "CLOSED"
		} else {
			class = "QUIET"
		}
	case "quiet":
		if hit.any() {
			class, fail = "LEAK", true
		} else {
			class = "QUIET"
		}
	case "owner":
		if st != 200 || !hit.secret {
			class, fail = "OWNER-FAIL", true
		} else {
			class = "OWNER-OK"
		}
	case "ownerpub":
		if st != 200 || !hit.pub || hit.secret {
			class, fail = "OWNER-FAIL", true
		} else {
			class = "OWNER-OK"
		}
	case "ownermail":
		if st != 200 || !hit.mail || hit.secret {
			class, fail = "OWNER-FAIL", true
		} else {
			class = "OWNER-OK"
		}
	case "ownercert":
		if st != 200 || !hit.cert || hit.secret {
			class, fail = "OWNER-FAIL", true
		} else {
			class = "OWNER-OK"
		}
	case "ownersig":
		if st != 200 || !hit.sig || hit.secret {
			class, fail = "OWNER-FAIL", true
		} else {
			class = "OWNER-OK"
		}
	case "ownerissued":
		if st != 200 || !hit.issued || hit.secret {
			class, fail = "OWNER-FAIL", true
		} else {
			class = "OWNER-OK"
		}
	case "control":
		if st != 200 || !strings.Contains(body, "ada") || hit.any() {
			class, fail = "CONTROL-FAIL", true
		} else {
			class = "CONTROL-OK"
		}
	default:
		t.Fatalf("bad mode %s", p.mode)
	}
	if fail {
		t.Errorf("%s %s: status=%d %s", class, p.name, st, hit)
	}
	q.stats.note(class, hit.secret)
	t.Logf("QA name=%s class=%s status=%d %s", p.name, class, st, hit)
	return st, hit
}

func wsStatus(rawURL, key string) (int, string) {
	hdr := http.Header{}
	if key != "" {
		hdr.Set("Authorization", "Bearer "+key)
	}
	d := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	c, resp, err := d.Dial(rawURL, hdr)
	if err != nil {
		if resp != nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return resp.StatusCode, string(b)
		}
		return 0, err.Error()
	}
	c.Close()
	return 101, ""
}

func linkTo(fromRec, field string) string {
	file, rest, _ := strings.Cut(fromRec, ":")
	tgt := `"rxa-lifetime-cert.red-xai.db":Record[ID=1]`
	if field != "" {
		tgt += "." + field
	}
	return `"` + file + `":` + rest + ` @> ` + tgt
}

// qaExtraRecords are adjacent shapes around the array-resolve gate.
// Field material is referenced only by building links; values stay in certBox.
func qaExtraRecords() [][2]string {
	p := func(id int) string { return fmt.Sprintf("players.red-xai.db:Player[ID=%d]", id) }
	lnk := func(id int, field string) string { return linkTo(p(id), field) }
	return [][2]string{
		{`notes.red-xai.db:Note[ID=30]`, `[ {Ptr[]} = ` + linkTo(`notes.red-xai.db:Note[ID=30]`, `owner_emails`) + ` ]`},
		// Nested array index. Expander records Bag[0][1].
		{p(13), `[ {Name[]} = "ada", {Bag[]} = ;[ ;[ "keep", ` + lnk(13, "issued") + ` ]: ]: ]`},
		// Cert link at index 1, not 0.
		{p(14), `[ {Name[]} = "ada", {Bag[]} = ;[ "keep", ` + lnk(14, "private_enc") + ` ]: ]`},
		// Link inside a box that is itself an array element. Path Bag[0].Steal.
		{p(15), `[ {Name[]} = "ada", {Bag[]} = ;[ [ {Steal[]} = ` + lnk(15, "pubkey") + ` ] ]: ]`},
		// Two-hop: array element points at a note whose field points at the cert.
		{p(16), `[ {Name[]} = "ada", {Bag[]} = ;["players.red-xai.db":Player[ID=16] @> "notes.red-xai.db":Note[ID=30]]: ]`},
		// ID attribute. EKey string is Bag[ID=0]; the array index is appended after it.
		{p(17), `[ {Name[]} = "ada", {Bag[ID=0]} = ;[` + lnk(17, "pubkey") + `]: ]`},
		{p(18), `[ {Name[]} = "ada", {Bag[ID=0]} = ;[` + lnk(18, "private_enc") + `]: ]`},
		{p(19), `[ {Name[]} = "ada", {Wrap[ID=3]} = [ {Bag[]} = ;[` + lnk(19, "cert_id") + `]: ] ]`},
		// Box field (not an array) whose entry carries an ID.
		{p(20), `[ {Name[]} = "ada", {Steal[ID=1]} = ` + lnk(20, "private_enc") + ` ]`},
		{p(21), `[ {Name[]} = "ada", {Bag[ID=2]} = ;[` + lnk(21, "pubkey") + `, ` + lnk(21, "cert_id") + `]: ]`},
		{p(22), `[ {Name[]} = "ada", {Bag[ID=0]} = ;[` + lnk(22, "") + `]: ]`},
		{p(23), `[ {Name[]} = "ada", {Bag[ID=4]} = ;[ ;[ "keep", ` + lnk(23, "sig_id_prefix") + ` ]: ]: ]`},
		{p(24), `[ {Name[]} = "ada", {Bag[]} = ;["players.red-xai.db":Player[ID=24] @> "rxa-lifetime-cert.red-xai":Record[ID=1].issued]: ]`},
		{p(25), `[ {Name[]} = "ada", {Bag[id=7]} = ;[` + lnk(25, "owner_emails") + `]: ]`},
		{p(26), `[ {Name[]} = "ada", {Hop[ID=1]} = "players.red-xai.db":Player[ID=26] @> "notes.red-xai.db":Note[ID=30] ]`},
		// Non-ID attribute. The recorded step stays Bag[0].
		{p(27), `[ {Name[]} = "ada", {Bag[Note="x"]} = ;[` + lnk(27, "pubkey") + `]: ]`},
		// Mixed-case attribute names. attrID folds them; EKey records [ID=n].
		{p(28), `[ {Name[]} = "ada", {Bag[Id=8]} = ;[` + lnk(28, "pubkey") + `]: ]`},
		{p(29), `[ {Name[]} = "ada", {Bag[iD=9]} = ;[` + lnk(29, "cert_id") + `]: ]`},
		// Rows that leaked at 6455153. EKey.String records [ID=] plus FormatInt,
		// including a leading minus and the minimum int64. A bare field read
		// must not return that entry to a non-owner. Source spellings are
		// folded to that recorded form before the step is compared.
		{p(30), `[ {Name[]} = "ada", {Bag[ID=-1]} = ;[` + lnk(30, "pubkey") + `]: ]`},
		{p(31), `[ {Name[]} = "ada", {Bag[ID=-2]} = ;[` + lnk(31, "private_enc") + `]: ]`},
		{p(32), `[ {Name[]} = "ada", {Wrap[ID=-3]} = [ {Bag[]} = ;[` + lnk(32, "cert_id") + `]: ] ]`},
		{p(33), `[ {Name[]} = "ada", {Steal[ID=-4]} = ` + lnk(33, "private_enc") + ` ]`},
		{p(34), `[ {Name[]} = "ada", {Bag[ID="-5"]} = ;[` + lnk(34, "owner_emails") + `]: ]`},
		{p(35), `[ {Name[]} = "ada", {Bag[-6]} = ;[` + lnk(35, "sig_id_prefix") + `]: ]`},
		{p(36), `[ {Name[]} = "ada", {Bag[ID="+7"]} = ;[` + lnk(36, "issued") + `]: ]`},
		// 1e20 and the int64 bounds do not survive float64 as a positive ID.
		{p(37), `[ {Name[]} = "ada", {Bag[ID=1e20]} = ;[` + lnk(37, "pubkey") + `]: ]`},
		{p(38), `[ {Name[]} = "ada", {Wrap[ID=11]} = [ {Bag[ID=12]} = ;[` + lnk(38, "cert_id") + `]: ] ]`},
		{p(39), `[ {Name[]} = "ada", {Hop[ID=-8]} = "players.red-xai.db":Player[ID=39] @> "notes.red-xai.db":Note[ID=30] ]`},
		{p(40), `[ {Name[]} = "ada", {Bag[ID=-9]} = ;[ ;[ "keep", ` + lnk(40, "issued") + ` ]: ]: ]`},
		{p(41), `[ {Name[]} = "ada", {Wrap[Id=-10]} = [ {Bag[id=3]} = ;[` + lnk(41, "pubkey") + `]: ] ]`},
		{p(42), `[ {Name[]} = "ada", {Bag[ID=007]} = ;[` + lnk(42, "cert_id") + `]: ]`},
		{p(43), `[ {Name[]} = "ada", {Bag[ID=1.5]} = ;[` + lnk(43, "pubkey") + `]: ]`},
		{p(44), `[ {Name[]} = "ada", {Steal[ID=15, Note="x"]} = ` + lnk(44, "owner_emails") + ` ]`},
		{p(45), `[ {Name[]} = "ada", {Bag[id="-11"]} = ;[` + lnk(45, "private_enc") + `]: ]`},
		{p(46), `[ {Name[]} = "ada", {Bag[ID=9223372036854775808]} = ;[` + lnk(46, "pubkey") + `]: ]`},
		{p(47), `[ {Name[]} = "ada", {Steal[ID=-9223372036854775808]} = ` + lnk(47, "private_enc") + ` ]`},
		{p(48), `[ {Name[]} = "ada", {Bag[ID=9223372036854775807]} = ;[` + lnk(48, "cert_id") + `]: ]`},
		{p(49), `[ {Name[]} = "ada", {Bag[ ID = -12 ]} = ;[` + lnk(49, "sig_id_prefix") + `]: ]`},
		// Oldest ID'd entry is the negative one. The positive sibling is not a cert link.
		{p(50), `[ {Name[]} = "ada", {Bag[ID=-20]} = ;[` + lnk(50, "private_enc") + `]:, {Bag[ID=20]} = ;["safe-note"]: ]`},
		{p(51), `[ {Name[]} = "ada", {Bag[ID="-0"]} = ;[` + lnk(51, "pubkey") + `]: ]`},
		{p(52), `[ {Name[]} = "ada", {Bag[ID=" -1"]} = ;[` + lnk(52, "pubkey") + `]: ]`},
		{p(53), `[ {Name[]} = "ada", {Bag[IDX=1]} = ;[` + lnk(53, "pubkey") + `]: ]`},
		{p(54), `[ {Name[]} = "ada", {Bag[ID]} = ;[` + lnk(54, "cert_id") + `]: ]`},
		{p(55), `[ {Name[]} = "ada", {Bag[ id = "-13" ]} = ;[` + lnk(55, "owner_emails") + `]: ]`},
		{p(56), `[ {Name[]} = "ada", {Bag[ID="1e2"]} = ;[` + lnk(56, "issued") + `]: ]`},
		// Adjacent spellings of a signed ID. Whole floats and values that do
		// not fit in int64 are stored with int64(float64) before FormatInt.
		{p(60), `[ {Name[]} = "ada", {Bag[ID=-1.0]} = ;[` + lnk(60, "pubkey") + `]: ]`},
		{p(61), `[ {Name[]} = "ada", {Bag[ID=-1e2]} = ;[` + lnk(61, "private_enc") + `]: ]`},
		{p(62), `[ {Name[]} = "ada", {Bag[ID=1e19]} = ;[` + lnk(62, "pubkey") + `]: ]`},
		{p(63), `[ {Name[]} = "ada", {Bag[ID=-1e20]} = ;[` + lnk(63, "private_enc") + `]: ]`},
		{p(64), `[ {Name[]} = "ada", {Bag[ID=1E20]} = ;[` + lnk(64, "cert_id") + `]: ]`},
		{p(65), `[ {Name[]} = "ada", {Bag[ID=1e18]} = ;[` + lnk(65, "private_enc") + `]: ]`},
		{p(66), `[ {Name[]} = "ada", {Steal[ID=-24, Note="x"]} = ` + lnk(66, "private_enc") + ` ]`},
		{p(67), `[ {Name[]} = "ada", {Bag[Note="z", ID=-25]} = ;[` + lnk(67, "pubkey") + `]: ]`},
		{p(68), `[ {Name[]} = "ada", {Bag[ID=-26]} = ;[ "keep", ` + lnk(68, "private_enc") + ` ]: ]`},
		{p(69), `[ {Name[]} = "ada", {Bag[]} = ;[ [ {Steal[ID=-27]} = ` + lnk(69, "private_enc") + ` ] ]: ]`},
		{p(70), `[ {Name[]} = "ada", {Wrap[ID=-28]} = [ {Bag[ID=-29]} = ;[` + lnk(70, "cert_id") + `]: ] ]`},
		{`notes.red-xai.db:Note[ID=71]`, `[ {Ptr[]} = "notes.red-xai.db":Note[ID=71] @> "notes.red-xai.db":Note[ID=30] ]`},
		{p(71), `[ {Name[]} = "ada", {Hop[ID=-31]} = "players.red-xai.db":Player[ID=71] @> "notes.red-xai.db":Note[ID=71] ]`},
		{p(72), `[ {Name[]} = "ada", {Bag[ID="-0002"]} = ;[` + lnk(72, "sig_id_prefix") + `]: ]`},
		{p(73), `[ {Name[]} = "ada", {Bag[ID="-9223372036854775808"]} = ;[` + lnk(73, "private_enc") + `]: ]`},
		{p(74), `[ {Name[]} = "ada", {Bag[ID="9223372036854775807"]} = ;[` + lnk(74, "cert_id") + `]: ]`},
		{p(75), `[ {Name[]} = "ada", {Steal[ID=-32]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc ]`},
		{p(76), `[ {Name[]} = "ada", {Steal[ID=-33]} = "players.red-xai.db":Player[ID=76] @!> "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc ]`},
		// Oldest entry is a positive cert link. The newer entry is a negative secret link.
		{p(77), `[ {Name[]} = "ada", {Bag[ID=40]} = ;[` + lnk(77, "pubkey") + `]:, {Bag[ID=-40]} = ;[` + lnk(77, "private_enc") + `]: ]`},
		// Oldest entry is not a cert. The newer entry is a positive secret link.
		{p(78), `[ {Name[]} = "ada", {Bag[ID=-41]} = ;["safe-note"]:, {Bag[ID=41]} = ;[` + lnk(78, "private_enc") + `]: ]`},
		{p(79), `[ {Name[]} = "ada", {Bag[ID=-0.0]} = ;[` + lnk(79, "issued") + `]: ]`},
		{p(80), `[ {Name[]} = "ada", {Bag[Id=-42]} = ;[` + lnk(80, "private_enc") + `]: ]`},
		{p(81), `[ {Name[]} = "ada", {Wrap[ID=-43]} = [ {Bag[]} = ` + lnk(81, "pubkey") + ` ] ]`},
		{p(82), `[ {Name[]} = "ada", {Bag[ID=-46]} = ;["players.red-xai.db":Player[ID=82] @> "rxa-lifetime-cert.red-xai":Record[ID=1].private_enc]: ]`},
		{`players.red-xai.db:Player[ID=-45]`, `[ {Name[]} = "ada", {Bag[]} = ;["players.red-xai.db":Player[ID=-45] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc]: ]`},
		{p(84), `[ {Name[]} = "ada", {Bag[ID=10.0]} = ;[` + lnk(84, "pubkey") + `]: ]`},
		{p(85), `[ {Name[]} = "ada", {Bag[ID=9.223372036854776e18]} = ;[` + lnk(85, "cert_id") + `]: ]`},
		{p(86), `[ {Name[]} = "ada", {Steal[ ID = -47 ]} = ` + lnk(86, "owner_emails") + ` ]`},
	}
}

// qaVar is one adjacent read. query includes the leading '?'. An empty method is GET.
type qaVar struct {
	name, method, path, query, mode string
	hdr                             []string
}

func qaIDVariants() []qaVar {
	p := func(id int, field string) string {
		if field == "" {
			return fmt.Sprintf("players.red-xai.db:Player[ID=%d]", id)
		}
		return fmt.Sprintf("players.red-xai.db:Player[ID=%d].%s", id, field)
	}
	h := func(accept string) []string { return []string{"Accept", accept} }
	return []qaVar{
		{"id url lowercase", "", p(17, "Bag[id=0]"), "?resolve=1&depth=4", "hunt", nil},
		{"id url mixed Id", "", p(17, "Bag[Id=0]"), "?resolve=1", "hunt", nil},
		{"id url mixed iD", "", p(17, "Bag[iD=0]"), "?resolve=1", "hunt", nil},
		{"id url spaces", "", p(17, "Bag[ ID = 0 ]"), "?resolve=1&depth=4", "hunt", nil},
		{"id wrong id", "", p(17, "Bag[ID=99]"), "?resolve=1&depth=4", "spot", nil},
		{"id any", "", p(17, "Bag[ID=*]"), "?resolve=1", "spot", nil},
		{"id star", "", p(17, "Bag[*]"), "?resolve=1", "spot", nil},
		{"id case bag", "", p(17, "bag"), "?resolve=1", "spot", nil},
		{"id longer name", "", p(17, "Baggage"), "?resolve=1", "spot", nil},
		{"id bag head", "HEAD", p(17, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"id secret accept star", "", p(18, "Bag"), "?resolve=1&depth=4", "hunt", h("*/*")},
		{"id secret accept html", "", p(18, "Bag"), "?resolve=1", "hunt", h("text/html")},
		{"id secret accept octet", "", p(18, "Bag"), "?resolve=1", "hunt", h("application/octet-stream")},
		{"id secret accept plain charset", "", p(18, "Bag"), "?resolve=1", "hunt", h("text/plain; charset=utf-8")},
		{"id secret accept json then plain", "", p(18, "Bag"), "?resolve=1", "hunt", h("application/json, text/plain")},
		{"id secret accept plain then json", "", p(18, "Bag"), "?resolve=1", "hunt", h("text/plain, application/json")},
		{"id secret param order", "", p(18, "Bag"), "?depth=4&resolve=1", "hunt", nil},
		{"id secret true depth32", "", p(18, "Bag"), "?resolve=true&depth=32", "hunt", h("text/plain")},
		{"id secret resolve TRUE", "", p(18, "Bag"), "?resolve=TRUE", "spot", nil},
		{"id secret resolve yes", "", p(18, "Bag"), "?resolve=yes", "spot", nil},
		{"id secret wrong negative", "", p(18, "Bag[ID=-2]"), "?resolve=1", "spot", nil},
		{"id secret head", "HEAD", p(18, "Bag"), "?resolve=1", "hunt", nil},
		{"id wrap url lowercase", "", p(19, "Wrap[id=3].Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"id wrap named parent", "", p(19, "Wrap[ID=3]"), "?resolve=1&depth=4", "hunt", nil},
		{"id wrap wrong id", "", p(19, "Wrap[ID=9].Bag"), "?resolve=1&depth=4", "spot", nil},
		{"id field url lowercase", "", p(20, "Steal[id=1]"), "?resolve=1", "hunt", h("text/plain")},
		{"id field head", "HEAD", p(20, "Steal"), "?resolve=1", "hunt", nil},
		{"id two depth1", "", p(21, "Bag"), "?resolve=1&depth=1", "hunt", nil},
		{"id nested named", "", p(23, "Bag[ID=4]"), "?resolve=1&depth=4", "hunt", nil},
		{"id lower canonical", "", p(25, "Bag[ID=7]"), "?resolve=1", "hunt", h("text/plain")},
		{"id lower url", "", p(25, "Bag[id=7]"), "?resolve=1&depth=4", "hunt", nil},
		{"id hop child", "", p(26, "Hop.Ptr"), "?resolve=1&depth=4", "hunt", nil},
		{"id hop depth1", "", p(26, "Hop"), "?resolve=1&depth=1", "spot", nil},
		{"id hop named", "", p(26, "Hop[ID=1]"), "?resolve=1&depth=4", "hunt", nil},
		{"id hop named child", "", p(26, "Hop[id=1].Ptr"), "?resolve=1&depth=4", "hunt", nil},
		{"array param order", "", p(8, "Bag"), "?depth=4&resolve=1", "must403", nil},
		{"array accept star", "", p(9, "Bag"), "?resolve=1", "must403", h("*/*")},
		{"array accept html", "", p(10, "Wrap.Bag"), "?resolve=1&depth=4", "must403", h("text/html")},
		{"mixed Id bag", "", p(28, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"mixed Id bag text", "", p(28, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"mixed Id bag named", "", p(28, "Bag[ID=8]"), "?resolve=1", "hunt", nil},
		{"mixed Id bag url", "", p(28, "Bag[Id=8]"), "?resolve=1", "hunt", nil},
		{"mixed iD bag", "", p(29, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"neg bag pubkey", "", p(30, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"neg bag pubkey text", "", p(30, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"neg bag pubkey true", "", p(30, "Bag"), "?resolve=true", "hunt", nil},
		{"neg bag named", "", p(30, "Bag[ID=-1]"), "?resolve=1&depth=4", "hunt", nil},
		{"neg bag bracket", "", p(30, "Bag[-1]"), "?resolve=1", "hunt", nil},
		{"neg bag url lowercase", "", p(30, "Bag[id=-1]"), "?resolve=1", "hunt", nil},
		{"neg bag record", "", p(30, ""), "?resolve=1&depth=4", "must403", nil},
		{"neg bag wrong id", "", p(30, "Bag[ID=99]"), "?resolve=1", "spot", nil},
		{"neg bag name", "", p(30, "Name"), "", "control", nil},
		{"neg secret", "", p(31, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"neg secret star", "", p(31, "Bag"), "?resolve=1&depth=4", "hunt", h("*/*")},
		{"neg secret json", "", p(31, "Bag"), "?resolve=1", "hunt", h("application/json")},
		{"neg secret box", "", p(31, "Bag"), "?resolve=1", "hunt", h("text/x-redx-box")},
		{"neg secret named", "", p(31, "Bag[ID=-2]"), "?resolve=1", "hunt", h("text/plain")},
		{"neg secret head", "HEAD", p(31, "Bag"), "?resolve=1", "hunt", nil},
		{"neg secret record", "", p(31, ""), "?resolve=1&depth=4", "must403", nil},
		{"neg wrap bag", "", p(32, "Wrap.Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"neg wrap parent", "", p(32, "Wrap"), "?resolve=1&depth=4", "hunt", nil},
		{"neg wrap named", "", p(32, "Wrap[ID=-3].Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"neg wrap url", "", p(32, "Wrap[id=-3]"), "?resolve=1&depth=4", "hunt", nil},
		{"neg wrap record", "", p(32, ""), "?resolve=1&depth=4", "must403", nil},
		{"neg field secret", "", p(33, "Steal"), "?resolve=1", "hunt", h("text/plain")},
		{"neg field named", "", p(33, "Steal[ID=-4]"), "?resolve=1", "hunt", nil},
		{"neg field bracket", "", p(33, "Steal[-4]"), "?resolve=1", "hunt", h("text/plain")},
		{"neg field record", "", p(33, ""), "?resolve=1&depth=4", "must403", nil},
		{"neg string mail", "", p(34, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"neg bare sig", "", p(35, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"plus string issued", "", p(36, "Bag"), "?resolve=1", "hunt", nil},
		{"overflow sci pubkey", "", p(37, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"overflow sci text", "", p(37, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"both id bag", "", p(38, "Wrap.Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"both id parent", "", p(38, "Wrap"), "?resolve=1&depth=4", "hunt", nil},
		{"both id named", "", p(38, "Wrap[ID=11].Bag[ID=12]"), "?resolve=1&depth=4", "hunt", nil},
		{"both id url", "", p(38, "Wrap[ID=11].Bag[id=12]"), "?resolve=1", "hunt", nil},
		{"neg hop", "", p(39, "Hop"), "?resolve=1&depth=4", "hunt", nil},
		{"neg hop depth1", "", p(39, "Hop"), "?resolve=1&depth=1", "spot", nil},
		{"neg hop named", "", p(39, "Hop[ID=-8]"), "?resolve=1&depth=4", "hunt", nil},
		{"neg hop child", "", p(39, "Hop.Ptr"), "?resolve=1&depth=4", "hunt", nil},
		{"neg nested", "", p(40, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"neg mixed wrap bag", "", p(41, "Wrap.Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"neg mixed wrap parent", "", p(41, "Wrap"), "?resolve=1&depth=4", "hunt", h("text/plain")},
		{"lead zero cert", "", p(42, "Bag"), "?resolve=1", "hunt", nil},
		{"fraction no id", "", p(43, "Bag"), "?resolve=1", "must403", nil},
		{"id plus note", "", p(44, "Steal"), "?resolve=1", "hunt", nil},
		{"lower neg secret", "", p(45, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"lower neg named", "", p(45, "Bag[ID=-11]"), "?resolve=1", "hunt", nil},
		{"overflow digits", "", p(46, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"minint secret", "", p(47, "Steal"), "?resolve=1", "hunt", h("text/plain")},
		{"minint named", "", p(47, "Steal[ID=-9223372036854775808]"), "?resolve=1", "hunt", nil},
		{"maxint cert", "", p(48, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"spaced neg sig", "", p(49, "Bag"), "?resolve=1", "hunt", nil},
		{"sibling neg secret", "", p(50, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"sibling neg record", "", p(50, ""), "?resolve=1&depth=4", "must403", nil},
		{"string neg zero", "", p(51, "Bag"), "?resolve=1", "hunt", nil},
		{"string space not id", "", p(52, "Bag"), "?resolve=1", "must403", nil},
		{"attr idx", "", p(53, "Bag"), "?resolve=1", "must403", nil},
		{"attr id flag", "", p(54, "Bag"), "?resolve=1", "must403", nil},
		{"spaced lower neg mail", "", p(55, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"string sci not id", "", p(56, "Bag"), "?resolve=1", "must403", nil},
		// Request spellings around the 6455153 bare-field leak.
		{"neg secret depth0", "", p(31, "Bag"), "?resolve=1&depth=0", "hunt", h("text/plain")},
		{"neg secret depth00", "", p(31, "Bag"), "?resolve=1&depth=00", "hunt", nil},
		{"neg secret resolve dup", "", p(31, "Bag"), "?resolve=1&depth=4&resolve=0", "hunt", h("text/plain")},
		{"neg secret resolve off first", "", p(31, "Bag"), "?resolve=0&resolve=1", "spot", nil},
		{"neg secret named pad", "", p(31, "Bag[ID=-02]"), "?resolve=1", "hunt", h("text/plain")},
		{"neg secret named space", "", p(31, "Bag[ ID = -2 ]"), "?resolve=1", "hunt", nil},
		{"neg secret post", "POST", p(31, "Bag"), "?resolve=1", "spot", nil},
		{"neg secret wild", "", p(31, "*"), "?resolve=1&depth=4", "spot", nil},
		{"sci stored min named", "", p(37, "Bag[ID=-9223372036854775808]"), "?resolve=1", "hunt", nil},
		{"maxlit stored min named", "", p(48, "Bag[ID=-9223372036854775808]"), "?resolve=1&depth=4", "hunt", nil},
		{"float neg one", "", p(60, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"float neg one text", "", p(60, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"float neg hundred", "", p(61, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"float neg hundred named", "", p(61, "Bag[ID=-100]"), "?resolve=1", "hunt", nil},
		{"overflow 1e19", "", p(62, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"overflow 1e19 text", "", p(62, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"overflow 1e19 named min", "", p(62, "Bag[ID=-9223372036854775808]"), "?resolve=1", "hunt", nil},
		{"overflow neg sci", "", p(63, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"overflow cap E", "", p(64, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"fit sci secret", "", p(65, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"fit sci named", "", p(65, "Bag[ID=1000000000000000000]"), "?resolve=1", "hunt", nil},
		{"neg id extra attr", "", p(66, "Steal"), "?resolve=1", "hunt", h("text/plain")},
		{"neg id not first", "", p(67, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"neg index1 secret", "", p(68, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"neg index1 depth4", "", p(68, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"inner neg steal", "", p(69, "Bag"), "?resolve=1&depth=4", "hunt", h("text/plain")},
		{"inner neg steal child", "", p(69, "Bag.Steal"), "?resolve=1&depth=4", "hunt", nil},
		{"both neg wrap bag", "", p(70, "Wrap.Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"both neg wrap parent", "", p(70, "Wrap"), "?resolve=1&depth=4", "hunt", nil},
		{"both neg named", "", p(70, "Wrap[ID=-28].Bag[ID=-29]"), "?resolve=1&depth=4", "hunt", nil},
		{"threehop", "", p(71, "Hop"), "?resolve=1&depth=4", "hunt", nil},
		{"threehop depth2", "", p(71, "Hop"), "?resolve=1&depth=2", "spot", nil},
		{"threehop child", "", p(71, "Hop.Ptr"), "?resolve=1&depth=4", "hunt", nil},
		{"string pad neg", "", p(72, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"string min secret", "", p(73, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"string min named", "", p(73, "Bag[ID=-9223372036854775808]"), "?resolve=1", "hunt", nil},
		{"string max cert", "", p(74, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"string max named", "", p(74, "Bag[ID=9223372036854775807]"), "?resolve=1", "hunt", nil},
		{"bare ref secret", "", p(75, "Steal"), "?resolve=1", "hunt", h("text/plain")},
		{"bare ref named", "", p(75, "Steal[ID=-32]"), "?resolve=1", "hunt", nil},
		{"cascade secret", "", p(76, "Steal"), "?resolve=1", "hunt", h("text/plain")},
		{"cascade named", "", p(76, "Steal[ID=-33]"), "?resolve=1", "hunt", nil},
		{"sibling pos oldest", "", p(77, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"sibling pos oldest named neg", "", p(77, "Bag[ID=-40]"), "?resolve=1", "hunt", nil},
		{"sibling safe oldest", "", p(78, "Bag"), "?resolve=1", "hunt", nil},
		{"sibling safe oldest named", "", p(78, "Bag[ID=41]"), "?resolve=1", "hunt", h("text/plain")},
		{"neg zero float", "", p(79, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"mixed neg secret", "", p(80, "Bag"), "?resolve=1", "hunt", h("text/plain")},
		{"mixed neg named", "", p(80, "Bag[ID=-42]"), "?resolve=1", "hunt", nil},
		{"neg wrap field bag", "", p(81, "Wrap.Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"neg wrap field parent", "", p(81, "Wrap"), "?resolve=1&depth=4", "hunt", h("text/plain")},
		{"short neg secret", "", p(82, "Bag"), "?resolve=1", "spot", nil},
		{"neg record bag", "", "players.red-xai.db:Player[ID=-45].Bag", "?resolve=1", "hunt", h("text/plain")},
		{"neg record bracket", "", "players.red-xai.db:Player[-45].Bag", "?resolve=1&depth=4", "hunt", nil},
		{"whole float ten", "", p(84, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"float near max", "", p(85, "Bag"), "?resolve=1&depth=4", "hunt", nil},
		{"float near max named min", "", p(85, "Bag[ID=-9223372036854775808]"), "?resolve=1", "hunt", nil},
		{"spaced neg mail", "", p(86, "Steal"), "?resolve=1", "hunt", nil},
		{"spaced neg mail named", "", p(86, "Steal[ID=-47]"), "?resolve=1", "hunt", nil},
	}
}

func TestQALifetimeCertAttack(t *testing.T) {
	stats := &qaStats{}
	t.Cleanup(func() { t.Logf("QA SUMMARY %s", stats.line()) })
	shortRec := `rxa-lifetime-cert.red-xai:Record[ID=1]`
	fullRec := `rxa-lifetime-cert.red-xai.db:Record[ID=1]`
	fields := []string{"pubkey", "cert_id", "owner_emails", "issued", "sig_id_prefix", "private_enc"}

	qs := startRealQA(t, nil)
	qs.stats = stats
	n := qs.node
	put := func(path, body string) {
		t.Helper()
		st, b, _ := do(t, "PUT", n.URL+"/v1/path/"+url.PathEscape(path), n.Key, body)
		if st != 200 || scanQA(b).any() {
			msg := b
			for _, s := range []string{qaMarker, qaPub, qaCert, qaMail, qaIssued, qaSig} {
				msg = strings.ReplaceAll(msg, s, "[field]")
			}
			if len(msg) > 240 {
				msg = msg[:240]
			}
			t.Fatalf("store %s: status=%d %s body=%s", path, st, scanQA(b), msg)
		}
	}
	put(fullRec, certBox())
	put(`players.red-xai.db:Player[ID=1]`, `[ {Name[]} = "ada", {Cert[]} = "players.red-xai.db":Player[ID=1] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1] ]`)
	put(`players.red-xai.db:Player[ID=2]`, `[ {Name[]} = "ada", {Steal[]} = `+linkTo(`players.red-xai.db:Player[ID=2]`, `pubkey`)+` ]`)
	put(`players.red-xai.db:Player[ID=3]`, `[ {Name[]} = "ada", {Steal[]} = `+linkTo(`players.red-xai.db:Player[ID=3]`, `private_enc`)+` ]`)
	put(`players.red-xai.db:Player[ID=4]`, `[ {Name[]} = "ada", {Steal[]} = `+linkTo(`players.red-xai.db:Player[ID=4]`, `cert_id`)+` ]`)
	put(`players.red-xai.db:Player[ID=5]`, `[ {Name[]} = "ada", {Steal[]} = `+linkTo(`players.red-xai.db:Player[ID=5]`, `owner_emails`)+` ]`)
	put(`players.red-xai.db:Player[ID=6]`, `[ {Name[]} = "ada", {Steal[]} = "players.red-xai.db":Player[ID=6] @> "rxa-lifetime-cert.red-xai":Record[ID=1].issued ]`)
	put(`players.red-xai.db:Player[ID=7]`, `[ {Name[]} = "ada", {Steal[]} = `+linkTo(`players.red-xai.db:Player[ID=7]`, `sig_id_prefix`)+` ]`)
	// Array element links. The expander records Bag[0]. This head claims the
	// request segment Bag selects that step. Non-owners must be 403.
	put(`players.red-xai.db:Player[ID=8]`, `[ {Name[]} = "ada", {Bag[]} = ;["players.red-xai.db":Player[ID=8] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].pubkey]: ]`)
	put(`players.red-xai.db:Player[ID=9]`, `[ {Name[]} = "ada", {Bag[]} = ;["players.red-xai.db":Player[ID=9] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc]: ]`)
	put(`players.red-xai.db:Player[ID=10]`, `[ {Name[]} = "ada", {Bag[]} = ;["players.red-xai.db":Player[ID=10] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1]]:, {Wrap[]} = [ {Bag[]} = ;["players.red-xai.db":Player[ID=10] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].cert_id]: ] ]`)
	put(`players.red-xai.db:Player[ID=11]`, `[ {Name[]} = "ada", {Meta[]} = [ {Steal[]} = `+linkTo(`players.red-xai.db:Player[ID=11]`, `issued`)+` ] ]`)
	put(`notes.red-xai.db:Note[ID=1]`, `[ {Ptr[]} = "notes.red-xai.db":Note[ID=1] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].owner_emails ]`)
	put(`players.red-xai.db:Player[ID=12]`, `[ {Name[]} = "ada", {Hop[]} = "players.red-xai.db":Player[ID=12] @> "notes.red-xai.db":Note[ID=1] ]`)
	for _, rec := range qaExtraRecords() {
		put(rec[0], rec[1])
	}
	for _, id := range []int{7, 8, 9, 11, 12} {
		put(fmt.Sprintf(`notes.red-xai.db:Note[ID=%d]`, id), `[ {text[]} = "placeholder" ]`)
	}

	wr, _ := mkKey(t, n, map[string]interface{}{"scope": "write", "db": "default"})
	base := n.URL
	db := base + "/v1/db/default"
	path := func(p string) string { return base + "/v1/path/" + url.PathEscape(p) }
	callers := []struct{ name, key string }{{"host-admin", n.Key}, {"write-key", wr}}

	for _, c := range callers {
		qs.probe(t, qaProbe{"control name " + c.name, "GET", path(`players.red-xai.db:Player[ID=1].Name`), c.key, "", "control", nil})
		qs.probe(t, qaProbe{"control name resolve " + c.name, "GET", path(`players.red-xai.db:Player[ID=1].Name`) + "?resolve=1", c.key, "", "control", nil})
		for _, f := range fields {
			qs.probe(t, qaProbe{"rest short " + f + " " + c.name, "GET", path(shortRec + "." + f), c.key, "", "must403", nil})
			qs.probe(t, qaProbe{"rest full " + f + " " + c.name, "GET", path(fullRec + "." + f), c.key, "", "must403", nil})
			qs.probe(t, qaProbe{"query short " + f + " " + c.name, "POST", db + "/query", c.key, shortRec + "." + f, "must403", nil})
			qs.probe(t, qaProbe{"query full " + f + " " + c.name, "POST", db + "/query", c.key, fullRec + "." + f, "must403", nil})
			qs.probe(t, qaProbe{"rest bare " + f + " " + c.name, "GET", path(`Record[ID=1].` + f), c.key, "", "must403", nil})
			qs.probe(t, qaProbe{"query star " + f + " " + c.name, "POST", db + "/query", c.key, `*.` + f, "must403", nil})
			qs.probe(t, qaProbe{"query record " + f + " " + c.name, "POST", db + "/query", c.key, `Record[ID=1].` + f, "must403", nil})
			qs.probe(t, qaProbe{"resolve dotted " + f + " " + c.name, "GET", path(`players.red-xai.db:Player[ID=1].Cert.`+f) + "?resolve=1", c.key, "", "must403", nil})
		}
		qs.probe(t, qaProbe{"rest short record " + c.name, "GET", path(shortRec), c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"rest full record " + c.name, "GET", path(fullRec), c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"rest bare record " + c.name, "GET", path(`Record[ID=1]`), c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"rest short pubkey text/plain " + c.name, "GET", path(shortRec + ".pubkey"), c.key, "", "must403", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"rest bare pubkey text/plain " + c.name, "GET", path(`Record[ID=1].pubkey`), c.key, "", "must403", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"rest bare private_enc text/plain " + c.name, "GET", path(`Record[ID=1].private_enc`), c.key, "", "must403", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"rest bare pubkey box " + c.name, "GET", path(`Record[ID=1].pubkey`), c.key, "", "must403", []string{"Accept", "text/x-redx-box"}})
		qs.probe(t, qaProbe{"rest head short pubkey " + c.name, "HEAD", path(shortRec + ".pubkey"), c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"rest head bare pubkey " + c.name, "HEAD", path(`Record[ID=1].pubkey`), c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"query short json owner_emails " + c.name, "POST", db + "/query", c.key, `{"q":"` + shortRec + `.owner_emails"}`, "must403", []string{"Content-Type", "application/json"}})
		qs.probe(t, qaProbe{"query json star pubkey " + c.name, "POST", db + "/query", c.key, `{"q":"*.pubkey"}`, "must403", []string{"Content-Type", "application/json"}})
		qs.probe(t, qaProbe{"query json star star " + c.name, "POST", db + "/query", c.key, `{"q":"*.*"}`, "must403", []string{"Content-Type", "application/json"}})
		qs.probe(t, qaProbe{"query json record star " + c.name, "POST", db + "/query", c.key, `{"q":"Record[ID=1].*"}`, "must403", []string{"Content-Type", "application/json"}})
		qs.probe(t, qaProbe{"query json record pubkey " + c.name, "POST", db + "/query", c.key, `{"q":"Record[ID=1].pubkey"}`, "must403", []string{"Content-Type", "application/json"}})
		qs.probe(t, qaProbe{"query star star " + c.name, "POST", db + "/query", c.key, `*.*`, "must403", nil})
		qs.probe(t, qaProbe{"query record star " + c.name, "POST", db + "/query", c.key, `Record[ID=1].*`, "must403", nil})
		qs.probe(t, qaProbe{"query record any pubkey " + c.name, "POST", db + "/query", c.key, `Record[ID=*].pubkey`, "must403", nil})
		qs.probe(t, qaProbe{"query wild id pubkey " + c.name, "POST", db + "/query", c.key, `*[ID=1].pubkey`, "must403", nil})
		qs.probe(t, qaProbe{"query wild id star " + c.name, "POST", db + "/query", c.key, `*[ID=1].*`, "must403", nil})
		qs.probe(t, qaProbe{"query star pubkey space " + c.name, "POST", db + "/query", c.key, "  *.pubkey\n", "must403", nil})
		qs.probe(t, qaProbe{"query prefix full " + c.name, "POST", db + "/query", c.key, `prefix:` + fullRec, "must403", nil})
		qs.probe(t, qaProbe{"query prefix short " + c.name, "POST", db + "/query", c.key, `prefix:rxa-lifetime-cert.red-xai`, "must403", nil})
		qs.probe(t, qaProbe{"query star " + c.name, "POST", db + "/query", c.key, `*`, "must403", nil})
		qs.probe(t, qaProbe{"query prefix loose " + c.name, "POST", db + "/query", c.key, `prefix:rxa`, "spot", nil})
		qs.probe(t, qaProbe{"rest resolve link " + c.name, "GET", path(`players.red-xai.db:Player[ID=1].Cert`) + "?resolve=1", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"rest resolve record depth " + c.name, "GET", path(`players.red-xai.db:Player[ID=1]`) + "?resolve=1&depth=2", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve dotted pubkey text/plain " + c.name, "GET", path(`players.red-xai.db:Player[ID=1].Cert.pubkey`) + "?resolve=1", c.key, "", "must403", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"resolve dotted pubkey depth " + c.name, "GET", path(`players.red-xai.db:Player[ID=1].Cert.pubkey`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve dotted pubkey true " + c.name, "GET", path(`players.red-xai.db:Player[ID=1].Cert.pubkey`) + "?resolve=true", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve field link pubkey " + c.name, "GET", path(`players.red-xai.db:Player[ID=2].Steal`) + "?resolve=1", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve field link private_enc " + c.name, "GET", path(`players.red-xai.db:Player[ID=3].Steal`) + "?resolve=1", c.key, "", "must403", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"resolve field link cert_id " + c.name, "GET", path(`players.red-xai.db:Player[ID=4].Steal`) + "?resolve=1", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve field link owner_emails " + c.name, "GET", path(`players.red-xai.db:Player[ID=5].Steal`) + "?resolve=1", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve field link issued short " + c.name, "GET", path(`players.red-xai.db:Player[ID=6].Steal`) + "?resolve=1", c.key, "", "spot", nil})
		qs.probe(t, qaProbe{"resolve field link sig " + c.name, "GET", path(`players.red-xai.db:Player[ID=7].Steal`) + "?resolve=1", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve meta steal " + c.name, "GET", path(`players.red-xai.db:Player[ID=11].Meta.Steal`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve meta parent " + c.name, "GET", path(`players.red-xai.db:Player[ID=11].Meta`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve hop ptr " + c.name, "GET", path(`players.red-xai.db:Player[ID=12].Hop.Ptr`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve hop parent " + c.name, "GET", path(`players.red-xai.db:Player[ID=12].Hop`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve array index " + c.name, "GET", path(`players.red-xai.db:Player[ID=8].Bag[0]`) + "?resolve=1&depth=4", c.key, "", "spot", nil})
		qs.probe(t, qaProbe{"resolve array index id form " + c.name, "GET", path(`players.red-xai.db:Player[ID=8].Bag[ID=0]`) + "?resolve=1", c.key, "", "spot", nil})
		qs.probe(t, qaProbe{"resolve array pubkey " + c.name, "GET", path(`players.red-xai.db:Player[ID=8].Bag`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve array pubkey text/plain " + c.name, "GET", path(`players.red-xai.db:Player[ID=8].Bag`) + "?resolve=1", c.key, "", "must403", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"resolve array pubkey box " + c.name, "GET", path(`players.red-xai.db:Player[ID=8].Bag`) + "?resolve=1", c.key, "", "must403", []string{"Accept", "text/x-redx-box"}})
		qs.probe(t, qaProbe{"resolve array pubkey true " + c.name, "GET", path(`players.red-xai.db:Player[ID=8].Bag`) + "?resolve=true", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve array pubkey depth1 " + c.name, "GET", path(`players.red-xai.db:Player[ID=8].Bag`) + "?resolve=1&depth=1", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve array pubkey depth32 " + c.name, "GET", path(`players.red-xai.db:Player[ID=8].Bag`) + "?resolve=1&depth=32", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve array pubkey head " + c.name, "HEAD", path(`players.red-xai.db:Player[ID=8].Bag`) + "?resolve=1", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve array private_enc " + c.name, "GET", path(`players.red-xai.db:Player[ID=9].Bag`) + "?resolve=1&depth=4", c.key, "", "must403", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"resolve array private_enc json " + c.name, "GET", path(`players.red-xai.db:Player[ID=9].Bag`) + "?resolve=1", c.key, "", "must403", []string{"Accept", "application/json"}})
		qs.probe(t, qaProbe{"resolve array whole " + c.name, "GET", path(`players.red-xai.db:Player[ID=10].Bag`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve nested array cert_id " + c.name, "GET", path(`players.red-xai.db:Player[ID=10].Wrap.Bag`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve nested array cert_id text " + c.name, "GET", path(`players.red-xai.db:Player[ID=10].Wrap.Bag`) + "?resolve=true", c.key, "", "must403", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"resolve nested wrap parent " + c.name, "GET", path(`players.red-xai.db:Player[ID=10].Wrap`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve array record " + c.name, "GET", path(`players.red-xai.db:Player[ID=8]`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve array record 9 " + c.name, "GET", path(`players.red-xai.db:Player[ID=9]`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve array record 10 " + c.name, "GET", path(`players.red-xai.db:Player[ID=10]`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve nested index issued " + c.name, "GET", path(`players.red-xai.db:Player[ID=13].Bag`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve nested index path " + c.name, "GET", path(`players.red-xai.db:Player[ID=13].Bag[0][1]`) + "?resolve=1", c.key, "", "spot", nil})
		qs.probe(t, qaProbe{"resolve array index1 secret " + c.name, "GET", path(`players.red-xai.db:Player[ID=14].Bag`) + "?resolve=1", c.key, "", "must403", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"resolve array element box " + c.name, "GET", path(`players.red-xai.db:Player[ID=15].Bag`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve array two-hop " + c.name, "GET", path(`players.red-xai.db:Player[ID=16].Bag`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve array two-hop depth1 " + c.name, "GET", path(`players.red-xai.db:Player[ID=16].Bag`) + "?resolve=1&depth=1", c.key, "", "spot", nil})
		qs.probe(t, qaProbe{"resolve id bag pubkey " + c.name, "GET", path(`players.red-xai.db:Player[ID=17].Bag`) + "?resolve=1&depth=4", c.key, "", "hunt", nil})
		qs.probe(t, qaProbe{"resolve id bag pubkey text " + c.name, "GET", path(`players.red-xai.db:Player[ID=17].Bag`) + "?resolve=1", c.key, "", "hunt", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"resolve id bag pubkey true " + c.name, "GET", path(`players.red-xai.db:Player[ID=17].Bag`) + "?resolve=true", c.key, "", "hunt", nil})
		qs.probe(t, qaProbe{"resolve id bag pubkey depth1 " + c.name, "GET", path(`players.red-xai.db:Player[ID=17].Bag`) + "?resolve=1&depth=1", c.key, "", "hunt", nil})
		qs.probe(t, qaProbe{"resolve id bag indexed " + c.name, "GET", path(`players.red-xai.db:Player[ID=17].Bag[ID=0]`) + "?resolve=1", c.key, "", "hunt", nil})
		qs.probe(t, qaProbe{"resolve id bag bracket " + c.name, "GET", path(`players.red-xai.db:Player[ID=17].Bag[0]`) + "?resolve=1", c.key, "", "hunt", nil})
		qs.probe(t, qaProbe{"resolve id bag record " + c.name, "GET", path(`players.red-xai.db:Player[ID=17]`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve id bag secret " + c.name, "GET", path(`players.red-xai.db:Player[ID=18].Bag`) + "?resolve=1", c.key, "", "hunt", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"resolve id bag secret json " + c.name, "GET", path(`players.red-xai.db:Player[ID=18].Bag`) + "?resolve=1&depth=4", c.key, "", "hunt", []string{"Accept", "application/json"}})
		qs.probe(t, qaProbe{"resolve id bag secret box " + c.name, "GET", path(`players.red-xai.db:Player[ID=18].Bag`) + "?resolve=1", c.key, "", "hunt", []string{"Accept", "text/x-redx-box"}})
		qs.probe(t, qaProbe{"resolve id wrap bag " + c.name, "GET", path(`players.red-xai.db:Player[ID=19].Wrap.Bag`) + "?resolve=1&depth=4", c.key, "", "hunt", nil})
		qs.probe(t, qaProbe{"resolve id wrap parent " + c.name, "GET", path(`players.red-xai.db:Player[ID=19].Wrap`) + "?resolve=1&depth=4", c.key, "", "hunt", nil})
		qs.probe(t, qaProbe{"resolve id wrap indexed " + c.name, "GET", path(`players.red-xai.db:Player[ID=19].Wrap[ID=3].Bag`) + "?resolve=1&depth=4", c.key, "", "hunt", nil})
		qs.probe(t, qaProbe{"resolve id wrap record " + c.name, "GET", path(`players.red-xai.db:Player[ID=19]`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve id field secret " + c.name, "GET", path(`players.red-xai.db:Player[ID=20].Steal`) + "?resolve=1", c.key, "", "hunt", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"resolve id field indexed " + c.name, "GET", path(`players.red-xai.db:Player[ID=20].Steal[ID=1]`) + "?resolve=1", c.key, "", "hunt", nil})
		qs.probe(t, qaProbe{"resolve id field record " + c.name, "GET", path(`players.red-xai.db:Player[ID=20]`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve id bag two fields " + c.name, "GET", path(`players.red-xai.db:Player[ID=21].Bag`) + "?resolve=1&depth=4", c.key, "", "hunt", nil})
		qs.probe(t, qaProbe{"resolve id bag whole " + c.name, "GET", path(`players.red-xai.db:Player[ID=22].Bag`) + "?resolve=1&depth=4", c.key, "", "must403", nil})
		qs.probe(t, qaProbe{"resolve id nested index " + c.name, "GET", path(`players.red-xai.db:Player[ID=23].Bag`) + "?resolve=1&depth=4", c.key, "", "hunt", nil})
		qs.probe(t, qaProbe{"resolve array short issued " + c.name, "GET", path(`players.red-xai.db:Player[ID=24].Bag`) + "?resolve=1", c.key, "", "spot", nil})
		qs.probe(t, qaProbe{"resolve id lowercase mail " + c.name, "GET", path(`players.red-xai.db:Player[ID=25].Bag`) + "?resolve=1&depth=4", c.key, "", "hunt", []string{"Accept", "text/plain"}})
		qs.probe(t, qaProbe{"resolve id hop mail " + c.name, "GET", path(`players.red-xai.db:Player[ID=26].Hop`) + "?resolve=1&depth=4", c.key, "", "hunt", nil})
		qs.probe(t, qaProbe{"resolve note attr pubkey " + c.name, "GET", path(`players.red-xai.db:Player[ID=27].Bag`) + "?resolve=1", c.key, "", "must403", nil})
		for _, v := range qaIDVariants() {
			method := v.method
			if method == "" {
				method = "GET"
			}
			qs.probe(t, qaProbe{v.name + " " + c.name, method, path(v.path) + v.query, c.key, "", v.mode, v.hdr})
		}
		qs.probe(t, qaProbe{"query neg secret bag " + c.name, "POST", db + "/query", c.key, `players.red-xai.db:Player[ID=31].Bag`, "spot", nil})
		qs.probe(t, qaProbe{"query neg secret star " + c.name, "POST", db + "/query", c.key, `players.red-xai.db:Player[ID=31].*`, "spot", nil})
		qs.probe(t, qaProbe{"query fit sci bag " + c.name, "POST", db + "/query", c.key, `players.red-xai.db:Player[ID=65].Bag`, "spot", nil})
		qs.probe(t, qaProbe{"resolve id bag noresolve " + c.name, "GET", path(`players.red-xai.db:Player[ID=18].Bag`), c.key, "", "spot", nil})
		qs.probe(t, qaProbe{"rest no-resolve field link pubkey " + c.name, "GET", path(`players.red-xai.db:Player[ID=2].Steal`), c.key, "", "quiet", nil})
		qs.probe(t, qaProbe{"rest not-a-prefix " + c.name, "GET", path(`rxa-lifetime-cert.red-xai.d:Record[ID=1].pubkey`), c.key, "", "quiet", nil})
		qs.probe(t, qaProbe{"rest stem red " + c.name, "GET", path(`rxa-lifetime-cert.red:Record[ID=1].issued`), c.key, "", "quiet", nil})
	}

	boxql := []struct{ name, q, mode string }{
		{"full pubkey", `{Get[]} = "rxa-lifetime-cert.red-xai.db":Record[ID=1] -> pubkey`, "must403"},
		{"short pubkey", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey`, "must403"},
		{"short cert_id", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> cert_id`, "must403"},
		{"short owner_emails", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> owner_emails`, "must403"},
		{"short issued", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> issued`, "must403"},
		{"short sig", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> sig_id_prefix`, "must403"},
		{"short private_enc", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> private_enc`, "must403"},
		{"short star", `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> *`, "must403"},
		{"link pubkey", `{Get[]} = players:Player[ID=1] -> [Name, Cert.pubkey] @> Cert`, "must403"},
		{"link cert_id", `{Get[]} = players:Player[ID=1] -> [Name, Cert.cert_id] @> Cert`, "must403"},
		{"link owner_emails", `{Get[]} = players:Player[ID=1] -> [Name, Cert.owner_emails] @> Cert`, "must403"},
		{"link issued", `{Get[]} = players:Player[ID=1] -> [Name, Cert.issued] @> Cert`, "must403"},
		{"link sig", `{Get[]} = players:Player[ID=1] -> [Name, Cert.sig_id_prefix] @> Cert`, "must403"},
		{"link private_enc", `{Get[]} = players:Player[ID=1] -> Cert.private_enc @> Cert`, "must403"},
		{"link whole", `{Get[]} = players:Player[ID=1] -> Cert @> Cert`, "must403"},
		{"link min pubkey", `{Get[]} = players:Player[ID=1] -> [Min(Cert.pubkey)] @> Cert`, "must403"},
		{"link left pubkey", `{Get[]} = players:Player[ID=1] -> [Name, Cert.pubkey] @> Cert ?`, "must403"},
		{"link filter pubkey", `{Get[]} = players:Player[Cert.pubkey = "` + qaPub + `"] -> Name @> Cert`, "must403"},
		{"link filter miss", `{Get[]} = players:Player[Cert.pubkey = "no-such-half"] -> Name @> Cert`, "must403"},
		{"field link pubkey", `{Get[]} = players:Player[ID=2] -> Steal @> Steal`, "must403"},
		{"field link private_enc", `{Get[]} = players:Player[ID=3] -> Steal @> Steal`, "must403"},
		{"bare record pubkey", `{Get[]} = Record[ID=1] -> pubkey`, "must403"},
		{"bare record star", `{Get[]} = Record[ID=1] -> *`, "must403"},
		{"star pubkey", `{Get[]} = * -> pubkey`, "spot"},
		{"record filter pubkey", `{Get[]} = Record[cert_id = "` + qaCert + `"] -> pubkey`, "spot"},
		{"array follow pubkey", `{Get[]} = players:Player[ID=8] -> Bag @> Bag`, "must403"},
		{"array follow private_enc", `{Get[]} = players:Player[ID=9] -> Bag @> Bag`, "must403"},
		{"array follow whole", `{Get[]} = players:Player[ID=10] -> Bag @> Bag`, "must403"},
		{"array follow nested", `{Get[]} = players:Player[ID=10] -> Wrap.Bag @> Wrap.Bag`, "must403"},
		{"array follow nested index", `{Get[]} = players:Player[ID=13] -> Bag @> Bag`, "spot"},
		{"array follow index1", `{Get[]} = players:Player[ID=14] -> Bag @> Bag`, "must403"},
		{"array follow element box", `{Get[]} = players:Player[ID=15] -> Bag @> Bag`, "spot"},
		{"array follow two-hop", `{Get[]} = players:Player[ID=16] -> Bag @> Bag`, "spot"},
		{"array follow id pubkey", `{Get[]} = players:Player[ID=17] -> Bag @> Bag`, "spot"},
		{"array follow id secret", `{Get[]} = players:Player[ID=18] -> Bag @> Bag`, "spot"},
		{"array follow id indexed", `{Get[]} = players:Player[ID=17] -> Bag[ID=0] @> Bag`, "spot"},
		{"array follow id wrap", `{Get[]} = players:Player[ID=19] -> Wrap.Bag @> Wrap.Bag`, "spot"},
		{"array follow id field", `{Get[]} = players:Player[ID=20] -> Steal @> Steal`, "spot"},
		{"array follow id two", `{Get[]} = players:Player[ID=21] -> Bag @> Bag`, "spot"},
		{"array follow id whole", `{Get[]} = players:Player[ID=22] -> Bag @> Bag`, "must403"},
		{"array follow mixed Id", `{Get[]} = players:Player[ID=28] -> Bag @> Bag`, "spot"},
		{"array follow neg pubkey", `{Get[]} = players:Player[ID=30] -> Bag @> Bag`, "spot"},
		{"array follow neg secret", `{Get[]} = players:Player[ID=31] -> Bag @> Bag`, "spot"},
		{"array follow neg wrap", `{Get[]} = players:Player[ID=32] -> Wrap.Bag @> Wrap.Bag`, "spot"},
		{"array follow neg field", `{Get[]} = players:Player[ID=33] -> Steal @> Steal`, "spot"},
		{"array follow overflow", `{Get[]} = players:Player[ID=37] -> Bag @> Bag`, "spot"},
		{"array follow both ids", `{Get[]} = players:Player[ID=38] -> Wrap.Bag @> Wrap.Bag`, "spot"},
		{"array follow neg hop", `{Get[]} = players:Player[ID=39] -> Hop @> Hop`, "spot"},
		{"array follow lower id", `{Get[]} = players:Player[ID=25] -> Bag @> Bag`, "spot"},
		{"array follow minint", `{Get[]} = players:Player[ID=47] -> Steal @> Steal`, "spot"},
		{"array follow sibling", `{Get[]} = players:Player[ID=50] -> Bag @> Bag`, "spot"},
		{"array follow float neg", `{Get[]} = players:Player[ID=61] -> Bag @> Bag`, "spot"},
		{"array follow fit sci", `{Get[]} = players:Player[ID=65] -> Bag @> Bag`, "spot"},
		{"array follow index1 neg", `{Get[]} = players:Player[ID=68] -> Bag @> Bag`, "spot"},
		{"array follow inner neg", `{Get[]} = players:Player[ID=69] -> Bag @> Bag`, "spot"},
		{"array follow both neg", `{Get[]} = players:Player[ID=70] -> Wrap.Bag @> Wrap.Bag`, "spot"},
		{"array follow threehop", `{Get[]} = players:Player[ID=71] -> Hop @> Hop`, "spot"},
		{"array follow bare ref", `{Get[]} = players:Player[ID=75] -> Steal @> Steal`, "spot"},
		{"array follow cascade", `{Get[]} = players:Player[ID=76] -> Steal @> Steal`, "spot"},
		{"array follow sibling pos", `{Get[]} = players:Player[ID=77] -> Bag @> Bag`, "spot"},
		{"array follow sibling safe", `{Get[]} = players:Player[ID=78] -> Bag @> Bag`, "spot"},
		{"array follow sibling safe named", `{Get[]} = players:Player[ID=78] -> Bag[ID=41] @> Bag`, "spot"},
		{"array follow neg record", `{Get[]} = players:Player[ID=-45] -> Bag @> Bag`, "spot"},
		{"array follow string max", `{Get[]} = players:Player[ID=74] -> Bag @> Bag`, "spot"},
		{"array follow near max", `{Get[]} = players:Player[ID=85] -> Bag @> Bag`, "spot"},
		{"get neg secret no follow", `{Get[]} = players:Player[ID=31] -> Bag`, "spot"},
		{"get neg secret star", `{Get[]} = players:Player[ID=31] -> *`, "spot"},
		{"alias neg secret", `{Get[]} = players:Player[ID=31] -> Bag @> secret = Bag`, "spot"},
		{"left neg secret", `{Get[]} = players:Player[ID=31] -> Bag @> Bag?`, "spot"},
		{"tx neg secret", `{Tx[]} = [ {Get[]} = players:Player[ID=31] -> Bag @> Bag ]`, "spot"},
		{"array follow lead zero", `{Get[]} = players:Player[ID=42] -> Bag @> Bag`, "spot"},
		{"explain short pubkey", `{Explain[]} = [ {Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey ]`, "must403"},
		{"explain follow pubkey", `{Explain[]} = [ {Get[]} = players:Player[ID=1] -> [Name, Cert.pubkey] @> Cert ]`, "spot"},
		{"explain bare pubkey", `{Explain[]} = [ {Get[]} = Record[ID=1] -> pubkey ]`, "spot"},
		{"tx short pubkey", `{Tx[]} = [ {Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey ]`, "must403"},
		{"tx bare pubkey", `{Tx[]} = [ {Get[]} = Record[ID=1] -> pubkey ]`, "spot"},
	}
	for _, c := range callers {
		for _, q := range boxql {
			qs.probe(t, qaProbe{"boxql " + q.name + " " + c.name, "POST", db + "/bx", c.key, q.q, q.mode, nil})
		}
		qs.probe(t, qaProbe{"boxql json bare pubkey " + c.name, "POST", db + "/bx", c.key, `{"q":"{Get[]} = Record[ID=1] -> pubkey"}`, "must403", []string{"Content-Type", "application/json"}})
		qs.probe(t, qaProbe{"boxql json explain bare " + c.name, "POST", db + "/bx", c.key, `{"q":"{Get[]} = Record[ID=1] -> pubkey","explain":true}`, "spot", []string{"Content-Type", "application/json"}})
	}

	// A second Record box must not leave the cert field in the combined result.
	put(`account.red-xai.db:Record[ID=1]`, `[ {username[]} = "ada" ]`)
	for _, c := range callers {
		qs.probe(t, qaProbe{"query record pubkey with sibling " + c.name, "POST", db + "/query", c.key, `Record[ID=1].pubkey`, "must403", nil})
		qs.probe(t, qaProbe{"query record star with sibling " + c.name, "POST", db + "/query", c.key, `Record[ID=1].*`, "must403", nil})
		qs.probe(t, qaProbe{"query star pubkey with sibling " + c.name, "POST", db + "/query", c.key, `*.pubkey`, "must403", nil})
		qs.probe(t, qaProbe{"query star star with sibling " + c.name, "POST", db + "/query", c.key, `*.*`, "must403", nil})
		qs.probe(t, qaProbe{"query json record star with sibling " + c.name, "POST", db + "/query", c.key, `{"q":"Record[ID=1].*"}`, "must403", []string{"Content-Type", "application/json"}})
		qs.probe(t, qaProbe{"rest bare pubkey with sibling " + c.name, "GET", path(`Record[ID=1].pubkey`), c.key, "", "quiet", nil})
		qs.probe(t, qaProbe{"boxql bare pubkey with sibling " + c.name, "POST", db + "/bx", c.key, `{Get[]} = Record[ID=1] -> pubkey`, "spot", nil})
		qs.probe(t, qaProbe{"control username with sibling " + c.name, "POST", db + "/query", c.key, `*.username`, "control", nil})
	}

	idx := `{ByCert[]} = [ {File[]} = "rxa-lifetime-cert.red-xai.db", {Box[]} = "Record", {Fields[]} = ;["cert_id"]:, {Kind[]} = "exact" ];
{ByPub[]} = [ {File[]} = "rxa-lifetime-cert.red-xai.db", {Box[]} = "Record", {Fields[]} = ;["pubkey"]:, {Kind[]} = "exact" ];
{ByPriv[]} = [ {File[]} = "rxa-lifetime-cert.red-xai.db", {Box[]} = "Record", {Fields[]} = ;["private_enc"]:, {Kind[]} = "exact" ];
{ByMail[]} = [ {File[]} = "rxa-lifetime-cert.red-xai.db", {Box[]} = "Record", {Fields[]} = ;["owner_emails"]:, {Kind[]} = "exact" ];`
	if st, b, _ := do(t, "PUT", db+"/idx/certs", n.Key, idx); st != 200 || scanQA(b).any() {
		t.Fatalf("index define: status=%d %s", st, scanQA(b))
	}
	for _, iq := range []struct{ name, index, field, value, extra string }{
		{"cert_id", "ByCert", "cert_id", qaCert, ""},
		{"pubkey", "ByPub", "pubkey", qaPub, ""},
		{"private_enc", "ByPriv", "private_enc", qaMarker, ""},
		{"owner_emails", "ByMail", "owner_emails", qaMail, ""},
		{"pubkey record", "ByPub", "pubkey", qaPub, "&record=1"},
		{"cert_id record", "ByCert", "cert_id", qaCert, "&record=1"},
		{"private_enc record", "ByPriv", "private_enc", qaMarker, "&record=1"},
	} {
		u := db + "/idx/certs/" + iq.index + "/query?mode=exact&field=" + url.QueryEscape(iq.field) + "&value=" + url.QueryEscape(iq.value) + iq.extra
		qs.probe(t, qaProbe{"index " + iq.name, "GET", u, wr, "", "must403", nil})
	}
	qs.probe(t, qaProbe{"index check", "GET", db + "/idx/certs/check", n.Key, "", "quiet", nil})
	qs.probe(t, qaProbe{"index list", "GET", db + "/idx", n.Key, "", "quiet", nil})

	src := `{Script[1]} = [
    {Name[]} = "readfield",
    {Params[]} = ;["target", "field"]:,
    {Uses[]} = ;["db_get"]:,
    {Source[]} = "return db_get(target, field);"
];`
	if st, b, _ := do(t, "PUT", db+"/code/file/steal", n.Key, src); st != 200 || scanQA(b).any() {
		t.Fatalf("script define: status=%d %s", st, scanQA(b))
	}
	run := func(label, target, field, key, mode string) {
		t.Helper()
		body, _ := json.Marshal(map[string]interface{}{"args": []interface{}{target, field}})
		qs.probe(t, qaProbe{"script " + label + " " + field, "POST", db + "/code/run/readfield", key, string(body), mode, []string{"Content-Type", "application/json"}})
	}
	for _, f := range fields {
		run("full write-key", fullRec, f, wr, "must403")
		run("short write-key", shortRec, f, wr, "must403")
		run("bare write-key", `Record[ID=1]`, f, wr, "spot")
		run("dotted write-key", `players.red-xai.db:Player[ID=1]`, "Cert."+f, wr, "spot")
	}
	run("link field write-key", `players.red-xai.db:Player[ID=1]`, "Cert", wr, "quiet")
	run("name control write-key", `players.red-xai.db:Player[ID=1]`, "Name", wr, "control")
	run("array bag write-key", `players.red-xai.db:Player[ID=8]`, "Bag", wr, "spot")
	run("id bag write-key", `players.red-xai.db:Player[ID=18]`, "Bag", wr, "spot")
	run("id field write-key", `players.red-xai.db:Player[ID=20]`, "Steal", wr, "spot")
	run("neg bag write-key", `players.red-xai.db:Player[ID=31]`, "Bag", wr, "spot")
	run("neg field write-key", `players.red-xai.db:Player[ID=33]`, "Steal", wr, "spot")
	run("float neg write-key", `players.red-xai.db:Player[ID=61]`, "Bag", wr, "spot")
	run("fit sci write-key", `players.red-xai.db:Player[ID=65]`, "Bag", wr, "spot")
	run("bare ref write-key", `players.red-xai.db:Player[ID=75]`, "Steal", wr, "spot")
	run("cascade write-key", `players.red-xai.db:Player[ID=76]`, "Steal", wr, "spot")

	rule := `{StealPub[ON="notes.red-xai.db:Note[ID=20].text"]} = [
    {When[]} = "== \"go\"",
    {SetTarget[]} = "\"notes.red-xai.db\":Note[ID=9].text = \"rxa-lifetime-cert.red-xai.db\":Record[ID=1].pubkey"
];
{StealSec[ON="notes.red-xai.db:Note[ID=21].text"]} = [
    {When[]} = "== \"go\"",
    {SetTarget[]} = "\"notes.red-xai.db\":Note[ID=8].text = \"rxa-lifetime-cert.red-xai.db\":Record[ID=1].private_enc"
];
{StealID[ON="notes.red-xai.db:Note[ID=22].text"]} = [
    {When[]} = "== \"go\"",
    {SetTarget[]} = "\"notes.red-xai.db\":Note[ID=7].text = \"rxa-lifetime-cert.red-xai\":Record[ID=1].cert_id"
];
`
	st, b, _ := do(t, "PUT", db+"/pulse", n.Key, rule)
	if scanQA(b).any() {
		t.Errorf("LEAK pulse define ack: status=%d %s", st, scanQA(b))
	}
	t.Logf("QA name=pulse define class=STATUS status=%d %s", st, scanQA(b))
	stats.note("STATUS", scanQA(b).secret)
	if st == 200 {
		put(`notes.red-xai.db:Note[ID=20].text`, `"go"`)
		put(`notes.red-xai.db:Note[ID=21].text`, `"go"`)
		put(`notes.red-xai.db:Note[ID=22].text`, `"go"`)
		time.Sleep(200 * time.Millisecond)
		for _, c := range callers {
			qs.probe(t, qaProbe{"pulse copy pubkey " + c.name, "GET", path(`notes.red-xai.db:Note[ID=9].text`), c.key, "", "spot", nil})
			qs.probe(t, qaProbe{"pulse copy private_enc " + c.name, "GET", path(`notes.red-xai.db:Note[ID=8].text`), c.key, "", "spot", nil})
			qs.probe(t, qaProbe{"pulse copy cert_id " + c.name, "GET", path(`notes.red-xai.db:Note[ID=7].text`), c.key, "", "spot", nil})
		}
	}
	qs.probe(t, qaProbe{"pulse define write-key", "PUT", db + "/pulse", wr, rule, "quiet", nil})

	wsBase := "ws" + strings.TrimPrefix(n.URL, "http")
	for _, p := range []struct{ name, path string }{
		{"full star", `rxa-lifetime-cert.red-xai.db:*`},
		{"short star", `rxa-lifetime-cert.red-xai:*`},
		{"short pubkey", shortRec + ".pubkey"},
		{"short record", shortRec},
	} {
		u := wsBase + "/v1/db/default/subscribe?path=" + url.QueryEscape(p.path)
		st, body := wsStatus(u, wr)
		hit := scanQA(body)
		class := "CLOSED"
		if hit.any() || st != 403 {
			class = "OPEN"
			if hit.any() {
				class = "LEAK"
			}
			t.Errorf("%s subscribe %s: status=%d %s", class, p.name, st, hit)
		}
		stats.note(class, hit.secret)
		t.Logf("QA name=subscribe %s class=%s status=%d %s", p.name, class, st, hit)
	}
	for _, q := range []string{
		`{Watch[]} = "rxa-lifetime-cert.red-xai.db":Record`,
		`{Watch[]} = "rxa-lifetime-cert.red-xai":Record`,
	} {
		u := wsBase + "/v1/db/default/bx/watch?q=" + url.QueryEscape(q)
		st, body := wsStatus(u, wr)
		hit := scanQA(body)
		class := "CLOSED"
		if hit.any() {
			class = "LEAK"
			t.Errorf("LEAK watch: status=%d %s", st, hit)
		} else if st == 101 {
			class = "UPGRADED"
			t.Errorf("OPEN watch upgraded with no field in the handshake")
		} else if st != 403 {
			class = "OPEN"
			t.Errorf("OPEN watch: status=%d %s", st, hit)
		}
		stats.note(class, hit.secret)
		t.Logf("QA name=watch %s class=%s status=%d %s", q, class, st, hit)
	}

	// Broad subscriptions must not deliver a cert field when one is written.
	watchFrames := func(name, rawURL, key string, touch func()) {
		t.Helper()
		hdr := http.Header{"Authorization": {"Bearer " + key}}
		c, resp, err := websocket.DefaultDialer.Dial(rawURL, hdr)
		if err != nil {
			st := 0
			body := ""
			if resp != nil {
				st = resp.StatusCode
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				body = string(b)
			}
			hit := scanQA(body)
			class := "QUIET"
			if hit.any() {
				class = "LEAK"
				t.Errorf("LEAK %s: status=%d %s", name, st, hit)
			}
			stats.note(class, hit.secret)
			t.Logf("QA name=%s class=%s status=%d %s", name, class, st, hit)
			return
		}
		defer c.Close()
		touch()
		_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		var frames []string
		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				break
			}
			frames = append(frames, string(msg))
			if len(frames) > 40 {
				break
			}
		}
		joined := strings.Join(frames, "\n")
		hit := scanQA(joined)
		pathHit := strings.Contains(joined, "rxa-lifetime-cert")
		class := "CLOSED"
		if hit.any() {
			class = "LEAK"
			t.Errorf("LEAK %s: frames=%d %s", name, len(frames), hit)
		}
		stats.note(class, hit.secret)
		t.Logf("QA name=%s class=%s status=101 frames=%d certpath=%v %s", name, class, len(frames), pathHit, hit)
	}
	watchFrames("subscribe star stream", wsBase+"/v1/db/default/subscribe?path="+url.QueryEscape("*"), wr, func() {
		put(`notes.red-xai.db:Note[ID=4].text`, `"hello-qa"`)
		put(fullRec+".touched", `"1"`)
	})
	watchFrames("subscribe record stream", wsBase+"/v1/db/default/subscribe?path="+url.QueryEscape("Record"), wr, func() {
		put(fullRec+".touched", `"2"`)
	})
	watchFrames("subscribe note-stream", wsBase+"/v1/db/default/subscribe?path="+url.QueryEscape(`notes.red-xai.db:*`), wr, func() {
		put(`notes.red-xai.db:Note[ID=5].text`, `"hello-qa"`)
		put(fullRec+".touched", `"3"`)
	})
	watchFrames("watch bare record", wsBase+"/v1/db/default/bx/watch?q="+url.QueryEscape(`{Watch[]} = Record`), wr, func() {
		put(`notes.red-xai.db:Note[ID=6].text`, `"hello-qa"`)
		put(fullRec+".touched", `"4"`)
	})

	st, b, _ = do(t, "GET", n.URL+"/v1/admin/backup", n.Key, "")
	raw := b
	if st == 200 {
		if zr, err := gzip.NewReader(strings.NewReader(b)); err == nil {
			buf, _ := io.ReadAll(io.LimitReader(zr, 8<<20))
			zr.Close()
			raw = string(buf)
		}
	}
	bhit := scanQA(raw)
	if st != 403 || bhit.any() {
		t.Errorf("LEAK backup: status=%d %s", st, bhit)
	}
	stats.note(map[bool]string{true: "LEAK", false: "CLOSED"}[st != 403 || bhit.any()], bhit.secret)
	t.Logf("QA name=backup class=%s status=%d %s", map[bool]string{true: "LEAK", false: "CLOSED"}[st != 403 || bhit.any()], st, bhit)

	for _, p := range []qaProbe{
		{"console audit", "GET", n.URL + "/v1/admin/audit?limit=50", n.Key, "", "quiet", nil},
		{"console files", "GET", db + "/files", n.Key, "", "quiet", nil},
		{"console file text", "GET", db + "/files/" + url.PathEscape("rxa-lifetime-cert.red-xai.db"), n.Key, "", "quiet", nil},
		{"cluster log", "GET", n.URL + "/v1/cluster/log", n.Key, "", "quiet", nil},
		{"stats", "GET", db + "/stats", n.Key, "", "quiet", nil},
		{"code list", "GET", db + "/code", n.Key, "", "quiet", nil},
	} {
		qs.probe(t, p)
	}

	// Accounts service key: write allowed, read-back forbidden.
	f, iss := startFake(t)
	acc := startRealQA(t, func(c *host.Config) {
		c.AccountsIssuer = iss
		c.AccountsClientSecret = "test-client-secret"
		c.AccountsEventsPoll = 3600
		c.OwnerEmails = []string{ownerA}
	})
	acc.stats = stats
	tok, acct := signIn(t, acc.node, f, ownerOK)
	if acct["owner"] != true {
		t.Fatalf("owner session was not elevated")
	}
	if st, _, _ := do(t, "POST", acc.URL+"/v1/dbs", tok, `{"name":"redxai_accounts"}`); st != 201 && st != 409 {
		t.Fatalf("master db: status=%d", st)
	}
	st, b, _ = do(t, "POST", acc.URL+"/v1/keys", tok, `{"db":"redxai_accounts","scope":"write","label":"accounts-service"}`, "Content-Type", "application/json")
	if st != 201 || scanQA(b).any() {
		t.Fatalf("service key: status=%d %s", st, scanQA(b))
	}
	svc := jsonOf(t, b)["key"].(string)
	mp := func(p string) string {
		return acc.URL + "/v1/db/redxai_accounts/path/" + url.PathEscape(p)
	}
	mst := acc.URL + "/v1/db/redxai_accounts"
	st, b, _ = do(t, "PUT", mp(fullRec), svc, certBox())
	if st != 200 || scanQA(b).any() {
		t.Fatalf("service write cert: status=%d %s", st, scanQA(b))
	}
	t.Logf("QA name=service write cert class=QUIET status=%d %s", st, scanQA(b))
	stats.note("QUIET", scanQA(b).secret)
	plink := `[ {Name[]} = "ada", {Cert[]} = "players.red-xai.db":Player[ID=1] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1] ]`
	if st, b, _ := do(t, "PUT", mp(`players.red-xai.db:Player[ID=1]`), svc, plink); st != 200 || scanQA(b).any() {
		t.Fatalf("service player link: status=%d %s", st, scanQA(b))
	}
	if st, b, _ := do(t, "PUT", mp(`players.red-xai.db:Player[ID=3]`), svc, `[ {Name[]} = "ada", {Steal[]} = `+linkTo(`players.red-xai.db:Player[ID=3]`, `private_enc`)+` ]`); st != 200 || scanQA(b).any() {
		t.Fatalf("service field link: status=%d %s", st, scanQA(b))
	}
	if st, b, _ := do(t, "PUT", mp(`players.red-xai.db:Player[ID=8]`), svc, `[ {Name[]} = "ada", {Bag[]} = ;["players.red-xai.db":Player[ID=8] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].pubkey]: ]`); st != 200 || scanQA(b).any() {
		t.Fatalf("service array link: status=%d %s", st, scanQA(b))
	}
	if st, b, _ := do(t, "PUT", mp(`players.red-xai.db:Player[ID=9]`), svc, `[ {Name[]} = "ada", {Bag[]} = ;["players.red-xai.db":Player[ID=9] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].private_enc]: ]`); st != 200 || scanQA(b).any() {
		t.Fatalf("service array secret link: status=%d %s", st, scanQA(b))
	}
	if st, b, _ := do(t, "PUT", mp(`players.red-xai.db:Player[ID=10]`), svc, `[ {Name[]} = "ada", {Bag[]} = ;["players.red-xai.db":Player[ID=10] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1]]:, {Wrap[]} = [ {Bag[]} = ;["players.red-xai.db":Player[ID=10] @> "rxa-lifetime-cert.red-xai.db":Record[ID=1].cert_id]: ] ]`); st != 200 || scanQA(b).any() {
		t.Fatalf("service nested array link: status=%d %s", st, scanQA(b))
	}
	for _, rec := range qaExtraRecords() {
		if st, b, _ := do(t, "PUT", mp(rec[0]), svc, rec[1]); st != 200 || scanQA(b).any() {
			msg := b
			for _, s := range []string{qaMarker, qaPub, qaCert, qaMail, qaIssued, qaSig} {
				msg = strings.ReplaceAll(msg, s, "[field]")
			}
			if len(msg) > 240 {
				msg = msg[:240]
			}
			t.Fatalf("service store %s: status=%d %s body=%s", rec[0], st, scanQA(b), msg)
		}
	}

	for _, f := range fields {
		acc.probe(t, qaProbe{"service rest short " + f, "GET", mp(shortRec + "." + f), svc, "", "must403", nil})
		acc.probe(t, qaProbe{"service query short " + f, "POST", mst + "/query", svc, shortRec + "." + f, "must403", nil})
		acc.probe(t, qaProbe{"service rest bare " + f, "GET", mp(`Record[ID=1].` + f), svc, "", "must403", nil})
		acc.probe(t, qaProbe{"service query star " + f, "POST", mst + "/query", svc, `*.` + f, "must403", nil})
		acc.probe(t, qaProbe{"service query record " + f, "POST", mst + "/query", svc, `Record[ID=1].` + f, "must403", nil})
		acc.probe(t, qaProbe{"service resolve dotted " + f, "GET", mp(`players.red-xai.db:Player[ID=1].Cert.`+f) + "?resolve=1", svc, "", "must403", nil})
	}
	acc.probe(t, qaProbe{"service rest bare pubkey text/plain", "GET", mp(`Record[ID=1].pubkey`), svc, "", "must403", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"service rest short record", "GET", mp(shortRec), svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service rest full record", "GET", mp(fullRec), svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service query star star", "POST", mst + "/query", svc, `*.*`, "must403", nil})
	acc.probe(t, qaProbe{"service query record star", "POST", mst + "/query", svc, `Record[ID=1].*`, "must403", nil})
	acc.probe(t, qaProbe{"service query wild id pubkey", "POST", mst + "/query", svc, `*[ID=1].pubkey`, "must403", nil})
	acc.probe(t, qaProbe{"service query json star pubkey", "POST", mst + "/query", svc, `{"q":"*.pubkey"}`, "must403", []string{"Content-Type", "application/json"}})
	acc.probe(t, qaProbe{"service query json record star", "POST", mst + "/query", svc, `{"q":"Record[ID=1].*"}`, "must403", []string{"Content-Type", "application/json"}})
	acc.probe(t, qaProbe{"service boxql short pubkey", "POST", mst + "/bx", svc, `{Get[]} = "rxa-lifetime-cert.red-xai":Record[ID=1] -> pubkey`, "must403", nil})
	acc.probe(t, qaProbe{"service boxql follow pubkey", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=1] -> [Name, Cert.pubkey] @> Cert`, "must403", nil})
	acc.probe(t, qaProbe{"service boxql follow cert_id", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=1] -> Cert.cert_id @> Cert`, "must403", nil})
	acc.probe(t, qaProbe{"service boxql follow owner_emails", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=1] -> Cert.owner_emails @> Cert`, "must403", nil})
	acc.probe(t, qaProbe{"service boxql follow private_enc", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=1] -> Cert.private_enc @> Cert`, "must403", nil})
	acc.probe(t, qaProbe{"service boxql bare pubkey", "POST", mst + "/bx", svc, `{Get[]} = Record[ID=1] -> pubkey`, "must403", nil})
	acc.probe(t, qaProbe{"service resolve dotted pubkey text/plain", "GET", mp(`players.red-xai.db:Player[ID=1].Cert.pubkey`) + "?resolve=1", svc, "", "must403", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"service resolve dotted cert_id depth", "GET", mp(`players.red-xai.db:Player[ID=1].Cert.cert_id`) + "?resolve=1&depth=4", svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service resolve field link private_enc", "GET", mp(`players.red-xai.db:Player[ID=3].Steal`) + "?resolve=1", svc, "", "must403", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"service resolve array pubkey", "GET", mp(`players.red-xai.db:Player[ID=8].Bag`) + "?resolve=1&depth=4", svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service resolve array pubkey text", "GET", mp(`players.red-xai.db:Player[ID=8].Bag`) + "?resolve=1", svc, "", "must403", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"service resolve array pubkey true", "GET", mp(`players.red-xai.db:Player[ID=8].Bag`) + "?resolve=true", svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service resolve array private_enc", "GET", mp(`players.red-xai.db:Player[ID=9].Bag`) + "?resolve=1", svc, "", "must403", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"service resolve nested array", "GET", mp(`players.red-xai.db:Player[ID=10].Wrap.Bag`) + "?resolve=1&depth=4", svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service resolve nested wrap", "GET", mp(`players.red-xai.db:Player[ID=10].Wrap`) + "?resolve=1&depth=4", svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service resolve array whole", "GET", mp(`players.red-xai.db:Player[ID=10].Bag`) + "?resolve=1&depth=4", svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service resolve array record", "GET", mp(`players.red-xai.db:Player[ID=9]`) + "?resolve=1&depth=4", svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service resolve nested index", "GET", mp(`players.red-xai.db:Player[ID=13].Bag`) + "?resolve=1&depth=4", svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service resolve array index1", "GET", mp(`players.red-xai.db:Player[ID=14].Bag`) + "?resolve=1", svc, "", "must403", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"service boxql array pubkey", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=8] -> Bag @> Bag`, "must403", nil})
	acc.probe(t, qaProbe{"service boxql array secret", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=9] -> Bag @> Bag`, "must403", nil})
	acc.probe(t, qaProbe{"service boxql nested array", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=10] -> Wrap.Bag @> Wrap.Bag`, "must403", nil})
	acc.probe(t, qaProbe{"service resolve id bag pubkey", "GET", mp(`players.red-xai.db:Player[ID=17].Bag`) + "?resolve=1&depth=4", svc, "", "hunt", nil})
	acc.probe(t, qaProbe{"service resolve id bag secret", "GET", mp(`players.red-xai.db:Player[ID=18].Bag`) + "?resolve=1", svc, "", "hunt", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"service resolve id bag indexed", "GET", mp(`players.red-xai.db:Player[ID=18].Bag[ID=0]`) + "?resolve=1", svc, "", "hunt", nil})
	acc.probe(t, qaProbe{"service resolve id wrap bag", "GET", mp(`players.red-xai.db:Player[ID=19].Wrap.Bag`) + "?resolve=1&depth=4", svc, "", "hunt", nil})
	acc.probe(t, qaProbe{"service resolve id wrap parent", "GET", mp(`players.red-xai.db:Player[ID=19].Wrap`) + "?resolve=1&depth=4", svc, "", "hunt", nil})
	acc.probe(t, qaProbe{"service resolve id field secret", "GET", mp(`players.red-xai.db:Player[ID=20].Steal`) + "?resolve=1", svc, "", "hunt", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"service resolve id bag two", "GET", mp(`players.red-xai.db:Player[ID=21].Bag`) + "?resolve=1&depth=4", svc, "", "hunt", nil})
	acc.probe(t, qaProbe{"service resolve id bag whole", "GET", mp(`players.red-xai.db:Player[ID=22].Bag`) + "?resolve=1&depth=4", svc, "", "must403", nil})
	acc.probe(t, qaProbe{"service resolve id nested", "GET", mp(`players.red-xai.db:Player[ID=23].Bag`) + "?resolve=1&depth=4", svc, "", "hunt", nil})
	acc.probe(t, qaProbe{"service resolve id mail", "GET", mp(`players.red-xai.db:Player[ID=25].Bag`) + "?resolve=1", svc, "", "hunt", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"service resolve id hop", "GET", mp(`players.red-xai.db:Player[ID=26].Hop`) + "?resolve=1&depth=4", svc, "", "hunt", nil})
	acc.probe(t, qaProbe{"service resolve note attr", "GET", mp(`players.red-xai.db:Player[ID=27].Bag`) + "?resolve=1", svc, "", "must403", nil})
	for _, v := range qaIDVariants() {
		method := v.method
		if method == "" {
			method = "GET"
		}
		acc.probe(t, qaProbe{"service " + v.name, method, mp(v.path) + v.query, svc, "", v.mode, v.hdr})
	}
	acc.probe(t, qaProbe{"service boxql id bag", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=18] -> Bag @> Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql neg secret", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=31] -> Bag @> Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql neg field", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=33] -> Steal @> Steal`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql neg wrap", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=32] -> Wrap.Bag @> Wrap.Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql overflow", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=37] -> Bag @> Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql mixed", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=28] -> Bag @> Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql sibling", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=50] -> Bag @> Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql float neg", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=61] -> Bag @> Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql fit sci", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=65] -> Bag @> Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql index1", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=68] -> Bag @> Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql both neg", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=70] -> Wrap.Bag @> Wrap.Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql bare ref", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=75] -> Steal @> Steal`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql cascade", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=76] -> Steal @> Steal`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql string max", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=74] -> Bag @> Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql neg record", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=-45] -> Bag @> Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service get neg no follow", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=31] -> Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service alias neg", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=31] -> Bag @> secret = Bag`, "spot", nil})
	acc.probe(t, qaProbe{"service left neg", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=31] -> Bag @> Bag?`, "spot", nil})
	acc.probe(t, qaProbe{"service boxql id field", "POST", mst + "/bx", svc, `{Get[]} = players:Player[ID=20] -> Steal @> Steal`, "spot", nil})
	acc.probe(t, qaProbe{"service explain follow", "POST", mst + "/bx", svc, `{Explain[]} = [ {Get[]} = players:Player[ID=1] -> Cert.pubkey @> Cert ]`, "spot", nil})
	acc.probe(t, qaProbe{"service script later", "POST", mst + "/code/run/readfield", svc, `{"args":["` + shortRec + `","pubkey"]}`, "spot", []string{"Content-Type", "application/json"}})

	if st, hit := acc.probe(t, qaProbe{"service set idVerified", "PUT", mp(`rxa-account.red-xai.db:Record[ID=1].idVerified`), svc, `{"value":true}`, "quiet", []string{"Content-Type", "application/json"}}); st != 200 || hit.any() {
		t.Errorf("service idVerified write: status=%d %s", st, hit)
	}
	acc.probe(t, qaProbe{"service query record star with sibling", "POST", mst + "/query", svc, `Record[ID=1].*`, "must403", nil})
	acc.probe(t, qaProbe{"service query star pubkey with sibling", "POST", mst + "/query", svc, `*.pubkey`, "must403", nil})
	acc.probe(t, qaProbe{"service rest bare pubkey with sibling", "GET", mp(`Record[ID=1].pubkey`), svc, "", "quiet", nil})
	acc.probe(t, qaProbe{"service control name", "GET", mp(`players.red-xai.db:Player[ID=1].Name`), svc, "", "control", nil})

	acc.probe(t, qaProbe{"owner full record", "GET", mp(fullRec), tok, "", "owner", nil})
	acc.probe(t, qaProbe{"owner short pubkey", "GET", mp(shortRec + ".pubkey"), tok, "", "ownerpub", nil})
	acc.probe(t, qaProbe{"owner query star pubkey", "POST", mst + "/query", tok, `*.pubkey`, "ownerpub", nil})
	acc.probe(t, qaProbe{"owner query record star", "POST", mst + "/query", tok, `Record[ID=1].*`, "owner", nil})
	acc.probe(t, qaProbe{"owner resolve pubkey", "GET", mp(`players.red-xai.db:Player[ID=1].Cert.pubkey`) + "?resolve=1", tok, "", "ownerpub", nil})
	acc.probe(t, qaProbe{"owner resolve private_enc", "GET", mp(`players.red-xai.db:Player[ID=3].Steal`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve array pubkey", "GET", mp(`players.red-xai.db:Player[ID=8].Bag`) + "?resolve=1&depth=4", tok, "", "ownerpub", nil})
	acc.probe(t, qaProbe{"owner resolve array private_enc", "GET", mp(`players.red-xai.db:Player[ID=9].Bag`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve nested array", "GET", mp(`players.red-xai.db:Player[ID=10].Wrap.Bag`) + "?resolve=1&depth=4", tok, "", "ownercert", nil})
	acc.probe(t, qaProbe{"owner resolve id bag pubkey", "GET", mp(`players.red-xai.db:Player[ID=17].Bag`) + "?resolve=1&depth=4", tok, "", "ownerpub", nil})
	acc.probe(t, qaProbe{"owner resolve id bag secret", "GET", mp(`players.red-xai.db:Player[ID=18].Bag`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve id field secret", "GET", mp(`players.red-xai.db:Player[ID=20].Steal`) + "?resolve=1", tok, "", "owner", nil})
	acc.probe(t, qaProbe{"owner resolve id wrap", "GET", mp(`players.red-xai.db:Player[ID=19].Wrap.Bag`) + "?resolve=1&depth=4", tok, "", "ownercert", nil})
	acc.probe(t, qaProbe{"owner resolve mixed Id", "GET", mp(`players.red-xai.db:Player[ID=28].Bag`) + "?resolve=1&depth=4", tok, "", "ownerpub", nil})
	acc.probe(t, qaProbe{"owner resolve neg bag", "GET", mp(`players.red-xai.db:Player[ID=30].Bag`) + "?resolve=1&depth=4", tok, "", "ownerpub", nil})
	acc.probe(t, qaProbe{"owner resolve neg secret", "GET", mp(`players.red-xai.db:Player[ID=31].Bag`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve neg wrap", "GET", mp(`players.red-xai.db:Player[ID=32].Wrap.Bag`) + "?resolve=1&depth=4", tok, "", "ownercert", nil})
	acc.probe(t, qaProbe{"owner resolve neg field", "GET", mp(`players.red-xai.db:Player[ID=33].Steal`) + "?resolve=1", tok, "", "owner", nil})
	acc.probe(t, qaProbe{"owner resolve both ids", "GET", mp(`players.red-xai.db:Player[ID=38].Wrap.Bag`) + "?resolve=1&depth=4", tok, "", "ownercert", nil})
	acc.probe(t, qaProbe{"owner resolve lower neg", "GET", mp(`players.red-xai.db:Player[ID=45].Bag`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve float neg one", "GET", mp(`players.red-xai.db:Player[ID=60].Bag`) + "?resolve=1&depth=4", tok, "", "ownerpub", nil})
	acc.probe(t, qaProbe{"owner resolve float hundred", "GET", mp(`players.red-xai.db:Player[ID=61].Bag`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve 1e19", "GET", mp(`players.red-xai.db:Player[ID=62].Bag`) + "?resolve=1", tok, "", "ownerpub", nil})
	acc.probe(t, qaProbe{"owner resolve fit sci", "GET", mp(`players.red-xai.db:Player[ID=65].Bag`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve index1", "GET", mp(`players.red-xai.db:Player[ID=68].Bag`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve inner neg", "GET", mp(`players.red-xai.db:Player[ID=69].Bag`) + "?resolve=1&depth=4", tok, "", "owner", nil})
	acc.probe(t, qaProbe{"owner resolve both neg", "GET", mp(`players.red-xai.db:Player[ID=70].Wrap.Bag`) + "?resolve=1&depth=4", tok, "", "ownercert", nil})
	acc.probe(t, qaProbe{"owner resolve threehop", "GET", mp(`players.red-xai.db:Player[ID=71].Hop`) + "?resolve=1&depth=4", tok, "", "ownermail", nil})
	acc.probe(t, qaProbe{"owner resolve string min", "GET", mp(`players.red-xai.db:Player[ID=73].Bag`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve string max", "GET", mp(`players.red-xai.db:Player[ID=74].Bag`) + "?resolve=1&depth=4", tok, "", "ownercert", nil})
	acc.probe(t, qaProbe{"owner resolve bare ref", "GET", mp(`players.red-xai.db:Player[ID=75].Steal`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve cascade", "GET", mp(`players.red-xai.db:Player[ID=76].Steal`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve sibling pos", "GET", mp(`players.red-xai.db:Player[ID=77].Bag`) + "?resolve=1", tok, "", "ownerpub", nil})
	acc.probe(t, qaProbe{"owner resolve sibling named", "GET", mp(`players.red-xai.db:Player[ID=78].Bag[ID=41]`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve neg zero", "GET", mp(`players.red-xai.db:Player[ID=79].Bag`) + "?resolve=1", tok, "", "ownerissued", nil})
	acc.probe(t, qaProbe{"owner resolve mixed neg", "GET", mp(`players.red-xai.db:Player[ID=80].Bag`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve neg record", "GET", mp(`players.red-xai.db:Player[ID=-45].Bag`) + "?resolve=1", tok, "", "owner", []string{"Accept", "text/plain"}})
	acc.probe(t, qaProbe{"owner resolve spaced", "GET", mp(`players.red-xai.db:Player[ID=86].Steal`) + "?resolve=1", tok, "", "ownermail", nil})
	acc.probe(t, qaProbe{"owner control name", "GET", mp(`players.red-xai.db:Player[ID=1].Name`), tok, "", "control", nil})

	if st, b, _ := do(t, "PUT", mst+"/code/file/steal", tok, src); st != 200 || scanQA(b).any() {
		t.Fatalf("owner script define: status=%d %s", st, scanQA(b))
	}
	for _, f := range []string{"pubkey", "cert_id", "owner_emails", "private_enc"} {
		body, _ := json.Marshal(map[string]interface{}{"args": []interface{}{shortRec, f}})
		acc.probe(t, qaProbe{"service script short " + f, "POST", mst + "/code/run/readfield", svc, string(body), "must403", []string{"Content-Type", "application/json"}})
		body, _ = json.Marshal(map[string]interface{}{"args": []interface{}{`Record[ID=1]`, f}})
		acc.probe(t, qaProbe{"service script bare " + f, "POST", mst + "/code/run/readfield", svc, string(body), "spot", []string{"Content-Type", "application/json"}})
	}

	st, b, _ = do(t, "GET", acc.URL+"/v1/admin/backup", acc.Key, "")
	raw = b
	if st == 200 {
		if zr, err := gzip.NewReader(bytes.NewReader([]byte(b))); err == nil {
			buf, _ := io.ReadAll(io.LimitReader(zr, 8<<20))
			zr.Close()
			raw = string(buf)
		}
	}
	bhit = scanQA(raw)
	class := "CLOSED"
	if st == 200 || bhit.any() {
		class = "LEAK"
		t.Errorf("LEAK accounts-on admin backup: status=%d %s", st, bhit)
	}
	stats.note(class, bhit.secret)
	t.Logf("QA name=accounts-on admin backup class=%s status=%d %s", class, st, bhit)

	// Host-admin is not the accounts service key. Master reads should not return cert fields.
	acc.probe(t, qaProbe{"host-admin master bare pubkey", "GET", mp(`Record[ID=1].pubkey`), acc.Key, "", "spot", nil})
	acc.probe(t, qaProbe{"host-admin master query star star", "POST", mst + "/query", acc.Key, `*.*`, "spot", nil})

	scanLogs(t, qs)
	scanLogs(t, acc)
}

func scanLogs(t *testing.T, qs *qaServer) {
	t.Helper()
	qs.mu.Lock()
	logs := strings.Join(qs.logs, "\n")
	nlines := len(qs.logs)
	qs.mu.Unlock()
	lh := scanQA(logs)
	pemN := strings.Count(logs, "-----BEGIN")
	pem := pemN > 0 || strings.Contains(logs, "PRIVATE KEY")
	if lh.any() || pem {
		t.Errorf("server log leak %s pem=%v", lh, pem)
	}
	class := map[bool]string{true: "LEAK", false: "CLOSED"}[lh.any() || pem]
	qs.stats.note(class, lh.secret)
	qs.stats.addPEM(pemN)
	t.Logf("QA name=server-log class=%s lines=%d %s pem=%v pem_banners=%d", class, nlines, lh, pem, pemN)

	auditHits := 0
	dataHits := 0
	pemHits := 0
	_ = filepath.Walk(qs.Dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || fi.Size() > 8<<20 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(qs.Dir, p)
		text := string(b)
		isAudit := strings.Contains(rel, "audit")
		if isAudit && (strings.Contains(text, "-----BEGIN") || strings.Contains(text, "PRIVATE KEY")) {
			pemHits++
		}
		if !strings.Contains(text, qaMarker) {
			return nil
		}
		if isAudit {
			auditHits++
			t.Errorf("audit file contains ciphertext marker: %s", rel)
		} else {
			dataHits++
		}
		return nil
	})
	t.Logf("QA name=leak-scan audit_files_with_ciphertext=%d pem_or_key_headers=%d data_files_with_stored_ciphertext=%d", auditHits, pemHits, dataHits)
}
