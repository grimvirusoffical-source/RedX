package host

import "net/http"

// guardUpdateMutation applies main's owner gates to one update call.
// topology: the call changes which nodes run which version (canary, blue-green, promote, rollback).
// masterBytes: the call snapshots or restores every database, including the master accounts database.
// While AccountsEnabled is false, masterDB is empty and the gates allow a host-admin through.
// While accounts are on, those calls are owner-only, the same as backup and cluster topology.
func (h *Host) guardUpdateMutation(w http.ResponseWriter, r *http.Request, pr *Principal, app string, topology, masterBytes bool) bool {
	if !h.refuseHiddenDB(w, r, pr, app) {
		return false
	}
	if (topology || masterBytes) && !h.ownerOnlyOK(w, r, pr) {
		return false
	}
	if masterBytes && !h.refuseMasterMutation(w, r, pr, h.masterDB()) {
		return false
	}
	return true
}
