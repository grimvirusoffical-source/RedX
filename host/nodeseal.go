package host

// Node-channel seal ("rxn1"): an end-to-end Red-SecretsXAI layer inside TLS for the
// cluster replication responses (/v1/cluster/log and /v1/cluster/snapshot).
//
// The follower sends
//
//	X-Redx-Seal: rxn1 <client nonce, 16 bytes, base64url>
//
// The leader answers with "X-Redx-Seal: rxn1 <fp>". fp is the SHA-256 of its own TLS
// certificate when it serves TLS itself, or "-" (plain HTTP, e.g. behind a proxy).
// The body is a Red-SecretsXAI RSX3 v2 stream under
//
//	K = HKDF-SHA256(ikm = node secret, salt = client nonce,
//	                info = "redx-node-seal v1" 0 node id 0 path 0 fingerprint)
//
// The node secret is the bearer secret already on the request; both ends know it.
// Channel binding: when the leader names a fingerprint, the follower derives K with
// the fingerprint of the certificate it actually received. If a TLS-intercepting
// middlebox sits in between, the two differ and the answer fails to authenticate
// (reported as possible interception). A leader that says "-" cannot be bound; the
// follower then logs once that the binding is unavailable.
// The RSX3 additional data binds the path, query, status, snapshot offset and
// replication id. Each pull gets a fresh nonce, so a fresh key. A truncated,
// reordered or replayed body does not authenticate.
//
// Compatibility (cluster_seal):
//   - "prefer" (default): seal when both ends support it. A pre-rxn1 leader
//     answers in plain TLS and the follower logs that once.
//   - "require": a follower refuses unsealed answers, and a leader refuses pulls
//     without the header (426).
//   - "off": do not ask for, or produce, the seal.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"redx/internal/rsx"
	"redx/internal/tlspin"
)

const (
	sealHeader = "X-Redx-Seal"
	sealV1     = "rxn1"
)

// ErrSealRequired: cluster_seal = "require" and the other end did not seal.
var ErrSealRequired = errors.New("cluster: the node channel is not sealed (rxn1) and cluster_seal = \"require\"")

func sealKey(secret string, nonce []byte, nodeID, path, fp string) ([]byte, error) {
	info := "redx-node-seal v1\x00" + nodeID + "\x00" + path + "\x00" + fp
	return rsx.HkdfSha256([]byte(secret), nonce, []byte(info), 32)
}

func sealAAD(path, rawQuery string, status int, offset, replid string) []byte {
	return []byte(sealV1 + "\x00" + path + "\x00" + rawQuery + "\x00" + strconv.Itoa(status) + "\x00" + offset + "\x00" + replid)
}

type sealReq struct {
	nonce []byte
}

func parseSealHeader(v string) (*sealReq, error) {
	f := strings.Fields(v)
	if len(f) != 2 || f[0] != sealV1 {
		return nil, errors.New("bad " + sealHeader + " header")
	}
	n, err := base64.RawURLEncoding.DecodeString(f[1])
	if err != nil || len(n) != 16 {
		return nil, errors.New("bad " + sealHeader + " nonce")
	}
	return &sealReq{nonce: n}, nil
}

func (c *Cluster) sealMode() string {
	switch m := c.h.Cfg.ClusterSeal; m {
	case "require", "off":
		return m
	}
	return "prefer"
}

// sealedResponse is the leader side. It returns a writer for the body plus a finish
// func, or ok=false after writing an error. The caller must not write headers itself.
func (c *Cluster) sealedResponse(w http.ResponseWriter, r *http.Request, nodeID string, status int, ctype, offset, replid string) (io.Writer, func() error, bool) {
	mode := c.sealMode()
	hv := r.Header.Get(sealHeader)
	if hv == "" || mode == "off" {
		if mode == "require" {
			writeErr(w, http.StatusUpgradeRequired, ErrSealRequired.Error())
			return nil, nil, false
		}
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(status)
		return w, func() error { return nil }, true
	}
	sr, err := parseSealHeader(hv)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return nil, nil, false
	}
	fp := "-"
	c.h.runMu.Lock()
	if r.TLS != nil && c.h.tlsFP != "" {
		fp = c.h.tlsFP
	}
	c.h.runMu.Unlock()
	k, err := sealKey(bearer(r), sr.nonce, nodeID, r.URL.Path, fp)
	if err != nil {
		writeErr(w, 500, "seal failed")
		return nil, nil, false
	}
	sess, err := rsx.NewSessionFromKey(k)
	rsx.Wipe(k)
	if err != nil {
		writeErr(w, 500, "seal failed")
		return nil, nil, false
	}
	w.Header().Set(sealHeader, sealV1+" "+fp)
	w.Header().Set("Content-Type", "application/vnd.redx.rxn1")
	w.WriteHeader(status)
	sw, err := sess.NewEncryptWriter(w, sealAAD(r.URL.Path, r.URL.RawQuery, status, offset, replid))
	if err != nil {
		sess.Close()
		return nil, nil, false
	}
	return sw, func() error { err := sw.Close(); sess.Close(); return err }, true
}

// writeNodeJSON writes v as JSON through sealedResponse.
func (c *Cluster) writeNodeJSON(w http.ResponseWriter, r *http.Request, nodeID string, status int, v interface{}) {
	b, err := jsonBytes(v)
	if err != nil {
		writeErr(w, 500, "encode failed")
		return
	}
	bw, finish, ok := c.sealedResponse(w, r, nodeID, status, "application/json", "", "")
	if !ok {
		return
	}
	_, _ = bw.Write(b)
	_ = finish()
}

// sealRequest is the follower side: it adds the header (unless off) and returns
// the state needed to open the answer.
func (c *Cluster) sealRequest(req *http.Request) (*sealReq, error) {
	if c.sealMode() == "off" {
		return nil, nil
	}
	n, err := rsx.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	req.Header.Set(sealHeader, sealV1+" "+base64.RawURLEncoding.EncodeToString(n))
	return &sealReq{nonce: n}, nil
}

// openSealed returns the plaintext body of resp. For a sealed answer the reader
// fails with an error unless the whole stream authenticates. The caller must
// read to EOF and check the error before acting on the data.
func (c *Cluster) openSealed(req *http.Request, resp *http.Response, sr *sealReq, offset, replid string) (io.Reader, func(), error) {
	if resp.Header.Get(sealHeader) == "" {
		if sr != nil && c.sealMode() == "require" {
			return nil, func() {}, ErrSealRequired
		}
		if sr != nil {
			c.sealWarn.Do(func() {
				c.h.Logf("cluster: the leader does not seal the node channel (rxn1); replication relies on TLS only. Upgrade it, or set cluster_seal = \"off\" to silence this")
			})
		}
		return resp.Body, func() {}, nil
	}
	f := strings.Fields(resp.Header.Get(sealHeader))
	if sr == nil || len(f) != 2 || f[0] != sealV1 {
		return nil, func() {}, errors.New("cluster: unexpected sealed answer")
	}
	fp, seen := f[1], ""
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		seen = tlspin.Fingerprint(resp.TLS.PeerCertificates[0].Raw)
	}
	switch {
	case fp == "-" && seen != "":
		c.bindWarn.Do(func() {
			c.h.Logf("cluster: the leader serves plain HTTP behind a TLS proxy; the rxn1 seal is used without TLS channel binding")
		})
	case fp != "-":
		if seen == "" {
			return nil, func() {}, errors.New("cluster: sealed answer names a TLS certificate, but the connection is not TLS")
		}
		fp = seen // a different certificate than the leader's own makes the stream fail below
	}
	c.mu.Lock()
	secret := c.st.NodeSecret
	c.mu.Unlock()
	if secret == "" {
		secret = c.h.Cfg.ClusterKey
	}
	k, err := sealKey(secret, sr.nonce, c.h.NodeID, req.URL.Path, fp)
	if err != nil {
		return nil, func() {}, err
	}
	sess, err := rsx.NewSessionFromKey(k)
	rsx.Wipe(k)
	if err != nil {
		return nil, func() {}, err
	}
	rd, err := sess.NewDecryptReader(resp.Body, sealAAD(req.URL.Path, req.URL.RawQuery, resp.StatusCode, offset, replid))
	if err != nil {
		sess.Close()
		return nil, func() {}, fmt.Errorf("cluster: sealed answer does not authenticate (wrong node secret, or TLS interception: the certificate seen here differs from the leader's): %w", err)
	}
	return &sealErrReader{rd}, sess.Close, nil
}

type sealErrReader struct{ r io.Reader }

func (s *sealErrReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && err != io.EOF {
		err = fmt.Errorf("cluster: sealed answer does not authenticate: %w", err)
	}
	return n, err
}

func jsonBytes(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(v)
	return buf.Bytes(), err
}
