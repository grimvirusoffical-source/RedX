package host

import (
	"net/http"
	"strings"
)

// ConfirmHeader is the explicit confirmation a dangerous operation needs.
// Value must be the operation id from api/redx-api.json (e.g. "createKey").
const ConfirmHeader = "X-RedX-Confirm"

// ConfirmRequired is the machine-readable code returned when a dangerous
// operation is called without confirmation (HTTP 428).
const ConfirmRequired = "confirm_required"

// dangerousOp is one API operation whose danger level is "dangerous".
// Kept in sync with api/redx-api.json by TestDangerousOpsMatchSpec.
// DangerousOp is one API operation whose danger level is "dangerous".
type DangerousOp struct {
	ID     string
	Method string
	// PathPattern uses "{name}" for a single path segment.
	PathPattern string
	// HostConfirm, if set, is the path/query parameter whose value also counts
	// as confirmation when sent as ?confirm=<value> (deleteDatabase: "db").
	HostConfirm string
}
type dangerousOp = DangerousOp

// dangerousOps is the full set of dangerous operations. A raw HTTP client that
// omits confirmation is refused for every one of these, regardless of key scope.
// DangerousOps returns the dangerous-operation table (tests + docs).
func DangerousOps() []dangerousOp { return append([]dangerousOp(nil), dangerousOps...) }

var dangerousOps = []dangerousOp{
	{ID: "deleteDatabase", Method: "DELETE", PathPattern: "/v1/db/{db}", HostConfirm: "db"},
	{ID: "createKey", Method: "POST", PathPattern: "/v1/keys"},
	{ID: "revokeKey", Method: "DELETE", PathPattern: "/v1/keys/{id}"},
	{ID: "rotateKey", Method: "POST", PathPattern: "/v1/keys/{id}/rotate"},
	{ID: "createPairingCode", Method: "POST", PathPattern: "/v1/keys/pairing"},
	{ID: "putPolicy", Method: "PUT", PathPattern: "/v1/db/{db}/sec"},
	{ID: "deletePolicy", Method: "DELETE", PathPattern: "/v1/db/{db}/sec"},
	{ID: "createJoinToken", Method: "POST", PathPattern: "/v1/cluster/join-token"},
	{ID: "promote", Method: "POST", PathPattern: "/v1/cluster/promote"},
	{ID: "repoint", Method: "POST", PathPattern: "/v1/cluster/leader"},
	{ID: "connectApprove", Method: "POST", PathPattern: "/v1/connect/approve"},
	{ID: "connectRevokeApp", Method: "DELETE", PathPattern: "/v1/connect/apps/{id}"},
	{ID: "updateApply", Method: "POST", PathPattern: "/v1/updates/apps/{app}/apply"},
	{ID: "updatePromote", Method: "POST", PathPattern: "/v1/updates/rollouts/{rollout_id}/promote"},
	{ID: "updateRolloutRollback", Method: "POST", PathPattern: "/v1/updates/rollouts/{rollout_id}/rollback"},
	{ID: "updateAppRollback", Method: "POST", PathPattern: "/v1/updates/apps/{app}/rollback"},
	{ID: "updatePublish", Method: "POST", PathPattern: "/v1/updates/apps/{app}/publish"},
}

// matchDangerous returns the dangerous operation for method+path, or nil.
// MatchDangerous identifies a dangerous operation for method+path (nil if none).
func MatchDangerous(method, path string) *DangerousOp { return matchDangerous(method, path) }

func matchDangerous(method, path string) *dangerousOp {
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}
	for i := range dangerousOps {
		op := &dangerousOps[i]
		if !strings.EqualFold(op.Method, method) {
			continue
		}
		params, ok := matchPath(op.PathPattern, path)
		if !ok {
			continue
		}
		_ = params
		return op
	}
	return nil
}

// matchPath matches /v1/db/{db}/sec against /v1/db/alpha/sec. Returns captured
// segments and true on a full match.
func matchPath(pattern, path string) (map[string]string, bool) {
	pp := strings.Split(strings.Trim(pattern, "/"), "/")
	ps := strings.Split(strings.Trim(path, "/"), "/")
	if len(pp) != len(ps) {
		return nil, false
	}
	out := map[string]string{}
	for i := range pp {
		if strings.HasPrefix(pp[i], "{") && strings.HasSuffix(pp[i], "}") {
			out[pp[i][1:len(pp[i])-1]] = ps[i]
			continue
		}
		if pp[i] != ps[i] {
			return nil, false
		}
	}
	return out, true
}

// confirmed reports whether the request carries an explicit confirmation for op.
// Accepted forms (any one is enough):
//   - header X-RedX-Confirm: <operation-id>
//   - query  ?confirm=<operation-id>
//   - for hostConfirm ops (deleteDatabase): ?confirm=<path-param-value> (kept for
//     compatibility; SDKs still send this when the call is confirmed)
func confirmed(r *http.Request, op *dangerousOp, pathParams map[string]string) bool {
	if v := strings.TrimSpace(r.Header.Get(ConfirmHeader)); v == op.ID {
		return true
	}
	q := r.URL.Query().Get("confirm")
	if q == "" {
		return false
	}
	if q == op.ID {
		return true
	}
	if op.HostConfirm != "" {
		if v, ok := pathParams[op.HostConfirm]; ok && q == v {
			return true
		}
	}
	return false
}

// requireDangerConfirm refuses a dangerous operation that lacks confirmation.
// Returns true when the request was refused (response already written).
func requireDangerConfirm(w http.ResponseWriter, r *http.Request) bool {
	op := matchDangerous(r.Method, r.URL.Path)
	if op == nil {
		return false
	}
	params, _ := matchPath(op.PathPattern, strings.TrimSuffix(r.URL.Path, "/"))
	if confirmed(r, op, params) {
		return false
	}
	writeErrCode(w, http.StatusPreconditionRequired, ConfirmRequired,
		op.ID+" is a dangerous operation and needs confirmation: send header "+ConfirmHeader+": "+op.ID+
			" (or ?confirm="+op.ID+")")
	return true
}

func writeErrCode(w http.ResponseWriter, status int, code, msg string) {
	if code == "" {
		noteReason(w, msg)
		code = errCodeFor(status)
	} else {
		noteReason(w, code)
	}
	writeAPIErr(w, status, msg, code, msg)
}
