package host

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// JoinSpec is what a new node needs to join a leader: where it is, the one-time secret and,
// for self-signed TLS, the certificate fingerprint to pin.
type JoinSpec struct {
	Leader string // http(s)://host:port
	Secret string // pairing code (RX-XXXXX-XXXXX) or rxj_ token
	Pin    string // sha256 hex of the leader's certificate (https)
}

// ParseJoin accepts the forms the console and the CLI produce:
//
//	https://192.168.1.5:7777/#/join?c=RX-ABCDE-FGHJK&pin=ab12...    (the link/QR from "Add a device")
//	https://192.168.1.5:7777 RX-ABCDE-FGHJK                          (URL and code as two words)
//	https://192.168.1.5:7777 rxj_...                                 (a long token)
func ParseJoin(arg string) (JoinSpec, error) {
	arg = strings.TrimSpace(arg)
	var sp JoinSpec
	if arg == "" {
		return sp, errors.New("empty join link")
	}
	if f := strings.Fields(arg); len(f) == 2 {
		sp.Leader, sp.Secret = f[0], f[1]
	} else if len(f) == 1 {
		u, err := url.Parse(f[0])
		if err != nil || u.Host == "" {
			return sp, errors.New("a join link looks like https://<leader>:7777/#/join?c=RX-XXXXX-XXXXX&pin=<fingerprint> (copy it from the leader's Add a device page)")
		}
		frag := u.Fragment
		if i := strings.Index(frag, "?"); i >= 0 {
			q, _ := url.ParseQuery(frag[i+1:])
			sp.Secret, sp.Pin = q.Get("c"), q.Get("pin")
			if sp.Secret == "" {
				sp.Secret = q.Get("t")
			}
		}
		if sp.Secret == "" {
			q := u.Query()
			sp.Secret, sp.Pin = q.Get("c"), q.Get("pin")
		}
		sp.Leader = u.Scheme + "://" + u.Host
	} else {
		return sp, errors.New("expected a join link or: <leader-url> <code>")
	}
	if !strings.Contains(sp.Leader, "://") {
		sp.Leader = "http://" + sp.Leader
	}
	lu, err := url.Parse(sp.Leader)
	if err != nil || lu.Host == "" || (lu.Scheme != "http" && lu.Scheme != "https") {
		return sp, fmt.Errorf("bad leader address %q", sp.Leader)
	}
	sp.Leader = lu.Scheme + "://" + lu.Host
	sp.Secret = NormalizeJoinSecret(sp.Secret)
	sp.Pin = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(sp.Pin)), "sha256:")
	if sp.Secret == "" {
		return sp, errors.New("the join link has no code; create a new one on the leader's Add a device page")
	}
	return sp, nil
}

// EnsureNodeID returns this data dir's node id, creating it if needed.
func EnsureNodeID(dataDir string) (string, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", err
	}
	return loadOrCreateNodeID(dataDir)
}

// HasJoined reports whether dataDir already has cluster state (so a join must not run again).
func HasJoined(dataDir string) bool {
	_, err := os.Stat(filepath.Join(dataDir, "cluster", "cluster.json"))
	return err == nil
}

// RedeemJoin performs the one-time handshake with the leader and writes cluster.json so the node
// starts as a follower. It never prints the secret.
func RedeemJoin(ctx context.Context, dataDir string, sp JoinSpec, advertise string) (nodeID string, err error) {
	nodeID, err = EnsureNodeID(dataDir)
	if err != nil {
		return "", err
	}
	cl := &http.Client{Timeout: 20 * time.Second}
	if strings.HasPrefix(sp.Leader, "https://") {
		if sp.Pin == "" {
			return "", errors.New("the leader uses https with a self-signed certificate: the join link must include its fingerprint (pin=...). Create the link on the leader's Add a device page")
		}
		cl.Transport = &http.Transport{TLSClientConfig: pinnedTLS(sp.Pin)}
	}
	jr, err := JoinLeader(ctx, cl, sp.Leader, sp.Secret, nodeID, advertise)
	if err != nil {
		return "", err
	}
	if err := WriteJoinedState(dataDir, sp.Leader, jr.NodeSecret, sp.Pin, advertise); err != nil {
		return "", err
	}
	return nodeID, nil
}
