package host

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"redx/internal/tlspin"
)

const sealSecret = "node-secret-for-seal-tests"

func sealCluster(mode, secret, nodeID string) *Cluster {
	h := &Host{Cfg: Config{ClusterSeal: mode}, NodeID: nodeID, Logf: func(string, ...interface{}) {}}
	c := &Cluster{h: h}
	c.st.NodeSecret = secret
	return c
}

// leaderServer serves body sealed (when asked) under the leader's view of its own
// certificate fingerprint. lieFP != "" simulates a leader whose certificate is not
// the one the follower received (TLS interception in between).
func leaderServer(t *testing.T, mode string, body []byte, lieFP string, truncate bool) (*httptest.Server, *Cluster) {
	lc := sealCluster(mode, "", "leader")
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bw, finish, ok := lc.sealedResponse(w, r, r.Header.Get("X-Redx-Node"), 200, "application/json", "7", "rid1")
		if !ok {
			return
		}
		_, _ = bw.Write(body)
		if !truncate {
			_ = finish()
		}
	})
	srv.StartTLS()
	lc.h.tlsFP = tlspin.Fingerprint(srv.Certificate().Raw)
	if lieFP != "" {
		lc.h.tlsFP = lieFP
	}
	return srv, lc
}

func pull(t *testing.T, fc *Cluster, srv *httptest.Server, secret, path, offset string) ([]byte, http.Header, error) {
	t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-Redx-Node", fc.h.NodeID)
	sr, err := fc.sealRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: tlspin.Config(tlspin.Fingerprint(srv.Certificate().Raw))}}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, resp.Header, errors.New(resp.Status + " " + string(b))
	}
	rd, done, err := fc.openSealed(req, resp, sr, offset, "rid1")
	if err != nil {
		return nil, resp.Header, err
	}
	defer done()
	b, err := io.ReadAll(rd)
	return b, resp.Header, err
}

func TestNodeSealRoundTripWithChannelBinding(t *testing.T) {
	body := bytes.Repeat([]byte(`{"entries":"replicated data"}`), 5000) // several RSX3 chunks
	srv, _ := leaderServer(t, "prefer", body, "", false)
	defer srv.Close()
	got, hdr, err := pull(t, sealCluster("prefer", sealSecret, "f1"), srv, sealSecret, "/v1/cluster/log?from=1", "7")
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("sealed pull: %v", err)
	}
	if !strings.HasPrefix(hdr.Get(sealHeader), "rxn1 "+tlspin.Fingerprint(srv.Certificate().Raw)) || hdr.Get("Content-Type") != "application/vnd.redx.rxn1" {
		t.Fatalf("answer not sealed with binding: %q %q", hdr.Get(sealHeader), hdr.Get("Content-Type"))
	}
	// The wire carries no plaintext: fetch raw.
	req, _ := http.NewRequest("GET", srv.URL+"/v1/cluster/log?from=1", nil)
	req.Header.Set("Authorization", "Bearer "+sealSecret)
	req.Header.Set(sealHeader, "rxn1 AAAAAAAAAAAAAAAAAAAAAA")
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: tlspin.Config(tlspin.Fingerprint(srv.Certificate().Raw))}}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(raw, []byte("replicated data")) {
		t.Fatal("sealed body contains plaintext")
	}
}

func TestNodeSealRejects(t *testing.T) {
	body := []byte(`{"entries":[1,2,3]}`)
	t.Run("interception", func(t *testing.T) {
		srv, _ := leaderServer(t, "prefer", body, strings.Repeat("ab", 32), false)
		defer srv.Close()
		if _, _, err := pull(t, sealCluster("prefer", sealSecret, "f1"), srv, sealSecret, "/v1/cluster/log", "7"); err == nil || !strings.Contains(err.Error(), "interception") {
			t.Fatalf("certificate mismatch accepted: %v", err)
		}
	})
	t.Run("wrong secret", func(t *testing.T) {
		srv, _ := leaderServer(t, "prefer", body, "", false)
		defer srv.Close()
		if _, _, err := pull(t, sealCluster("prefer", "other secret", "f1"), srv, sealSecret, "/v1/cluster/log", "7"); err == nil {
			t.Fatal("wrong node secret accepted")
		}
	})
	t.Run("wrong node id", func(t *testing.T) {
		srv, _ := leaderServer(t, "prefer", body, "", false)
		defer srv.Close()
		fc := sealCluster("prefer", sealSecret, "f1")
		req, _ := http.NewRequest("GET", srv.URL+"/v1/cluster/log", nil)
		req.Header.Set("Authorization", "Bearer "+sealSecret)
		req.Header.Set("X-Redx-Node", "f2") // key is bound to the id the leader authenticated
		sr, _ := fc.sealRequest(req)
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: tlspin.Config(tlspin.Fingerprint(srv.Certificate().Raw))}}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if rd, done, err := fc.openSealed(req, resp, sr, "7", "rid1"); err == nil {
			_, err = io.ReadAll(rd)
			done()
			if err == nil {
				t.Fatal("answer for another node id accepted")
			}
		}
	})
	t.Run("truncated", func(t *testing.T) {
		srv, _ := leaderServer(t, "prefer", bytes.Repeat([]byte("x"), 200000), "", true)
		defer srv.Close()
		if _, _, err := pull(t, sealCluster("prefer", sealSecret, "f1"), srv, sealSecret, "/v1/cluster/log", "7"); err == nil {
			t.Fatal("truncated stream accepted")
		}
	})
	t.Run("changed offset header", func(t *testing.T) {
		srv, _ := leaderServer(t, "prefer", body, "", false)
		defer srv.Close()
		if _, _, err := pull(t, sealCluster("prefer", sealSecret, "f1"), srv, sealSecret, "/v1/cluster/log", "8"); err == nil {
			t.Fatal("answer with a different authenticated offset accepted")
		}
	})
}

func TestNodeSealCompatibility(t *testing.T) {
	body := []byte(`{"ok":true}`)
	// A pre-rxn1 leader: ignores the header and answers in plain TLS.
	var asked atomic.Bool
	old := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Store(r.Header.Get(sealHeader) != "")
		_, _ = w.Write(body)
	}))
	defer old.Close()
	got, _, err := pull(t, sealCluster("prefer", sealSecret, "f1"), old, sealSecret, "/v1/cluster/log", "7")
	if err != nil || !bytes.Equal(got, body) || !asked.Load() {
		t.Fatalf("prefer with an old leader: %v %q", err, got)
	}
	if _, _, err := pull(t, sealCluster("require", sealSecret, "f1"), old, sealSecret, "/v1/cluster/log", "7"); !errors.Is(err, ErrSealRequired) {
		t.Fatalf("require with an old leader: %v", err)
	}
	if _, _, err := pull(t, sealCluster("off", sealSecret, "f1"), old, sealSecret, "/v1/cluster/log", "7"); err != nil || asked.Load() {
		t.Fatalf("off must not ask for the seal: %v", err)
	}
	// A pre-rxn1 follower (no header) against a new leader.
	srv, _ := leaderServer(t, "prefer", body, "", false)
	defer srv.Close()
	got, hdr, err := pull(t, sealCluster("off", sealSecret, "f1"), srv, sealSecret, "/v1/cluster/log", "7")
	if err != nil || !bytes.Equal(got, body) || hdr.Get(sealHeader) != "" {
		t.Fatalf("old follower against a prefer leader: %v", err)
	}
	strict, _ := leaderServer(t, "require", body, "", false)
	defer strict.Close()
	if _, _, err := pull(t, sealCluster("off", sealSecret, "f1"), strict, sealSecret, "/v1/cluster/log", "7"); err == nil || !strings.Contains(err.Error(), "426") {
		t.Fatalf("require leader must refuse unsealed pulls with 426: %v", err)
	}
}
