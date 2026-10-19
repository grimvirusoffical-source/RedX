package host_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"redx/host"
	"redx/host/internal/stubstore"
)

// tlsNode is a node serving https with its own self-signed certificate (tls=auto), like a real redxd.
type tlsNode struct {
	H      *host.Host
	URL    string
	Addr   string
	Dir    string
	FP     string
	Key    string
	cancel context.CancelFunc
	done   chan struct{}
}

var insecureTestClient = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

func doTLS(t *testing.T, method, url, key, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := insecureTestClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func startTLSNode(t *testing.T, dir, addr string, mod func(c *host.Config)) *tlsNode {
	t.Helper()
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ { // a restart reuses the port; give the OS a moment
		if ln, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	n := &tlsNode{Dir: dir, Addr: ln.Addr().String(), done: make(chan struct{})}
	n.URL = "https://" + n.Addr
	cfg := baseCfg(dir)
	cfg.TLS = "auto"
	cfg.Advertise = n.URL
	if mod != nil {
		mod(&cfg)
	}
	h, err := host.New(cfg, func(d string, follower bool) (host.Backend, error) { return stubstore.Open(d, follower) }, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	n.H, n.Key = h, h.BootstrapKey
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	go func() { defer close(n.done); _ = h.Serve(ctx, ln) }()
	eventually(t, "tls node up", 5*time.Second, func() bool { st, _ := doTLS(t, "GET", n.URL+"/healthz", "", ""); return st == 200 })
	fp, err := host.Fingerprint(filepath.Join(dir, "tls", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	n.FP = fp
	t.Cleanup(n.Stop)
	return n
}

func (n *tlsNode) Stop() {
	if n.cancel != nil {
		n.cancel()
		<-n.done
		n.cancel = nil
	}
}

func tlsStatus(t *testing.T, n *tlsNode, key string) host.ClusterStatus {
	t.Helper()
	st, b := doTLS(t, "GET", n.URL+"/v1/cluster/status", key, "")
	if st != 200 {
		t.Fatalf("status %d %s", st, b)
	}
	var cs host.ClusterStatus
	if err := jsonUnmarshal(b, &cs); err != nil {
		t.Fatal(err)
	}
	return cs
}

func tlsToken(t *testing.T, n *tlsNode, key string) string {
	t.Helper()
	st, b := doTLS(t, "POST", n.URL+"/v1/cluster/join-token", key, `{"ttl_seconds":60}`)
	if st != 200 {
		t.Fatalf("join-token %d %s", st, b)
	}
	return jsonOf(t, b)["token"].(string)
}

// a: leader; b: joined as follower over pinned TLS; both self-signed.
func tlsPair(t *testing.T) (a, b *tlsNode) {
	a = startTLSNode(t, t.TempDir(), "", func(c *host.Config) { c.NodeID = "a" })
	b = startTLSNode(t, t.TempDir(), "", func(c *host.Config) { c.NodeID = "b" })
	body := fmt.Sprintf(`{"url":%q,"join_token":%q,"pin_sha256":%q}`, a.URL, tlsToken(t, a, a.Key), a.FP)
	if st, out := doTLS(t, "POST", b.URL+"/v1/cluster/leader", b.Key, body); st != 200 {
		t.Fatalf("b joins a over pinned TLS: %d %s", st, out)
	}
	if st, _ := doTLS(t, "PUT", a.URL+P+"t:B.One", a.Key, "1"); st != 200 {
		t.Fatal("write on a")
	}
	eventually(t, "b replicates a over TLS", 8*time.Second, func() bool {
		st, _ := doTLS(t, "GET", b.URL+P+"t:B.One", a.Key, "")
		return st == 200
	})
	return a, b
}

func leaders(t *testing.T, key string, ns ...*tlsNode) (n int) {
	for _, x := range ns {
		cs := tlsStatus(t, x, key)
		if cs.Role == "leader" && cs.Fenced == nil {
			n++
		}
	}
	return n
}

// with self-signed TLS, promote + repoint must end with exactly one leader, and a reachable old
// leader stops taking writes as soon as the new one is promoted.
func TestTLSPromoteRepointOneLeaderAndFence(t *testing.T) {
	a, b := tlsPair(t)
	k := a.Key
	if st, out := doTLS(t, "POST", b.URL+"/v1/cluster/promote", k, ""); st != 200 {
		t.Fatalf("promote b: %d %s", st, out)
	}
	if cs := tlsStatus(t, b, k); cs.Role != "leader" || cs.LastError != "" {
		t.Fatalf("after promote b must be leader with no stale last error: role=%s last_error=%q", cs.Role, cs.LastError)
	}
	// the old leader is told over the pinned channel and refuses writes: no split brain
	eventually(t, "a fenced", 15*time.Second, func() bool { return tlsStatus(t, a, k).Fenced != nil })
	if st, out := doTLS(t, "PUT", a.URL+P+"t:B.Split", k, "2"); st != 503 || !strings.Contains(out, "repoint") {
		t.Fatalf("fenced old leader must refuse writes with 503, got %d %s", st, out)
	}
	if st, _ := doTLS(t, "GET", a.URL+P+"t:B.One", k, ""); st != 200 {
		t.Fatal("a fenced node still serves reads")
	}
	if n := leaders(t, k, a, b); n != 1 {
		t.Fatalf("want exactly one writable leader after promote, got %d", n)
	}
	fence := tlsStatus(t, a, k).Fenced
	if fence.LeaderURL != b.URL || fence.Pin != b.FP {
		t.Fatalf("fence should carry the new leader's URL and pin: %+v", fence)
	}
	// repoint with no --leader-pin: the pin learned through the fence is used
	body := fmt.Sprintf(`{"url":%q,"join_token":%q}`, b.URL, tlsToken(t, b, k))
	if st, out := doTLS(t, "POST", a.URL+"/v1/cluster/leader", k, body); st != 200 {
		t.Fatalf("repoint a -> b over self-signed TLS: %d %s", st, out)
	}
	if st, _ := doTLS(t, "PUT", b.URL+P+"t:B.Two", k, "3"); st != 200 {
		t.Fatal("write on new leader")
	}
	eventually(t, "a follows b", 10*time.Second, func() bool {
		st, _ := doTLS(t, "GET", a.URL+P+"t:B.Two", k, "")
		return st == 200
	})
	csA := tlsStatus(t, a, k)
	if csA.Role != "follower" || csA.Fenced != nil || csA.LastError != "" {
		t.Fatalf("a after repoint: role=%s fenced=%v last_error=%q", csA.Role, csA.Fenced, csA.LastError)
	}
	if n := leaders(t, k, a, b); n != 1 {
		t.Fatalf("want exactly one leader after repoint, got %d", n)
	}
	// a write sent to the demoted node is forwarded to the one leader
	if st, out := doTLS(t, "PUT", a.URL+P+"t:B.Fwd", k, "4"); st != 200 {
		t.Fatalf("forwarded write via a: %d %s", st, out)
	}
}

// Repoint to a self-signed leader the node has no trust for: a clear error naming --leader-pin; with the
// pin (what `redx node repoint --leader-pin` sends) it works.
func TestTLSRepointNeedsPinAndAcceptsExplicitPin(t *testing.T) {
	a, b := tlsPair(t)
	k := a.Key
	host.PartitionFenceNotify(t) // a is never told, so it has no learned pin
	if st, out := doTLS(t, "POST", b.URL+"/v1/cluster/promote", k, ""); st != 200 {
		t.Fatalf("promote: %d %s", st, out)
	}
	body := fmt.Sprintf(`{"url":%q,"join_token":%q}`, b.URL, tlsToken(t, b, k))
	st, out := doTLS(t, "POST", a.URL+"/v1/cluster/leader", k, body)
	if st == 200 || !strings.Contains(out, "--leader-pin") {
		t.Fatalf("repoint without trust must fail with a --leader-pin hint: %d %s", st, out)
	}
	if cs := tlsStatus(t, a, k); cs.Role != "leader" {
		t.Fatalf("a failed repoint must leave the node as it was, got %s", cs.Role)
	}
	body = fmt.Sprintf(`{"url":%q,"join_token":%q,"pin_sha256":%q}`, b.URL, tlsToken(t, b, k), b.FP)
	if st, out := doTLS(t, "POST", a.URL+"/v1/cluster/leader", k, body); st != 200 {
		t.Fatalf("repoint with explicit pin: %d %s", st, out)
	}
	if n := leaders(t, k, a, b); n != 1 {
		t.Fatalf("want exactly one leader, got %d", n)
	}
}

// The old leader is down while the follower is promoted; when it comes back it is fenced within about
// one heartbeat (writes in that window are the documented residual hazard).
func TestTLSOldLeaderFencedWhenItComesBack(t *testing.T) {
	a, b := tlsPair(t)
	k := a.Key
	addr, dir := a.Addr, a.Dir
	a.Stop()
	if st, out := doTLS(t, "POST", b.URL+"/v1/cluster/promote", k, ""); st != 200 {
		t.Fatalf("promote: %d %s", st, out)
	}
	a2 := startTLSNode(t, dir, addr, func(c *host.Config) { c.NodeID = "a" })
	eventually(t, "restarted old leader fenced", 8*time.Second, func() bool { return tlsStatus(t, a2, k).Fenced != nil })
	if st, _ := doTLS(t, "PUT", a2.URL+P+"t:B.Late", k, "x"); st != 503 {
		t.Fatalf("fenced restarted leader must refuse writes, got %d", st)
	}
	// the fence survives another restart (stored in cluster.json)
	a2.Stop()
	a3 := startTLSNode(t, dir, addr, func(c *host.Config) { c.NodeID = "a" })
	if cs := tlsStatus(t, a3, k); cs.Fenced == nil {
		t.Fatal("fence must persist across restarts")
	}
	// an operator can deliberately take over again (promote on a fenced leader clears the fence)
	if st, out := doTLS(t, "POST", a3.URL+"/v1/cluster/promote", k, ""); st != 200 || !strings.Contains(out, "fence cleared") {
		t.Fatalf("unfence: %d %s", st, out)
	}
}

// A member that was not promoted from this leader's history cannot fence it.
func TestSupersededNeedsPromotedHistory(t *testing.T) {
	a, _ := tlsPair(t)
	st, _ := doTLS(t, "POST", a.URL+"/v1/cluster/superseded", "", `{"leader_url":"https://evil:1","parent_id":"x"}`)
	if st != 401 {
		t.Fatalf("unauthenticated superseded must be 401, got %d", st)
	}
	if cs := tlsStatus(t, a, a.Key); cs.Fenced != nil {
		t.Fatal("must not be fenced")
	}
}

func jsonUnmarshal(s string, v interface{}) error { return json.Unmarshal([]byte(s), v) }
