package host_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"redx/host"
)

// Two nodes with cluster_seal = "require" replicate (log and the initial
// snapshot), and the leader's live log answer is an rxn1 stream, not JSON.
func TestClusterSealRequireReplicates(t *testing.T) {
	const secret = "s3cret-shared-value-for-seal"
	leader := startNode(t, t.TempDir(), func(c *host.Config, _ string) { c.ClusterKey, c.ClusterSeal = secret, "require" })
	do(t, "PUT", leader.URL+P+"z:B.K", leader.Key, `"sealed"`)
	f := startNode(t, t.TempDir(), func(c *host.Config, _ string) {
		c.ClusterKey, c.ClusterSeal = secret, "require"
		c.Role, c.Peers, c.NodeID = "follower", []string{leader.URL}, "sealed1"
	})
	eventually(t, "sealed follower replicates", 10*time.Second, func() bool {
		st, b, _ := do(t, "GET", f.URL+P+"z:B.K", leader.Key, "")
		return st == 200 && strings.Contains(b, "sealed")
	})
	req, _ := http.NewRequest("GET", leader.URL+"/v1/cluster/log?from=1&limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-Redx-Node", "probe")
	req.Header.Set("X-Redx-Seal", "rxn1 AAAAAAAAAAAAAAAAAAAAAA")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-Redx-Seal") != "rxn1 -" || resp.Header.Get("Content-Type") != "application/vnd.redx.rxn1" {
		t.Fatalf("live log answer not sealed: %q %q", resp.Header.Get("X-Redx-Seal"), resp.Header.Get("Content-Type"))
	}
	// An unsealed pull is refused by a require leader.
	req.Header.Del("X-Redx-Seal")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("unsealed pull: %d", resp.StatusCode)
	}
}

func TestClusterSealConfigValidated(t *testing.T) {
	c := baseCfg(t.TempDir())
	c.ClusterSeal = "maybe"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "cluster_seal") {
		t.Fatalf("bad cluster_seal: %v", err)
	}
}
