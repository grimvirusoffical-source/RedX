package host

import "fmt"

// The legacy replication callback does not certify this record's replicated
// commit. This capability promises local standalone durability only.
// The caller holds recordGate so membership cannot change during the operation.
func (c *Cluster) recordCASMode() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.members) != 0 || len(c.h.Cfg.Peers) != 0 || c.h.Cfg.ClusterKey != "" || c.meta.ParentID != "" || c.st.Former != nil {
		return fmt.Errorf("%w: record CAS requires a standalone leader without replication membership or promoted history", ErrUnavailable)
	}
	return nil
}
