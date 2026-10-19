package host

import (
	"errors"
	"net/http"
	"time"

	"redx/billing"
)

// writeQuotaErr writes a clear 402/429 with an upgrade hint for hosted-plan caps.
func writeQuotaErr(w http.ResponseWriter, err error) bool {
	var qe *billing.ErrQuota
	if !errors.As(err, &qe) {
		return false
	}
	writeJSON(w, qe.HTTP, map[string]string{
		"error": qe.Code, "message": qe.Message, "upgrade": "/ui/billing.html",
	})
	return true
}

// hostedAccount returns the Red-XAI Account sub when the principal is signed in
// with a paid Hosted plan. API-key-only callers get ok=false (self-hosted: no caps).
func (h *Host) hostedAccount(pr *Principal) (account string, q billing.Quota, periodEnd time.Time, ok bool) {
	if h == nil || h.billing == nil || pr == nil || pr.Account == nil || pr.Account.Sub == "" {
		return "", billing.Quota{}, time.Time{}, false
	}
	// Owners administer the host; quotas apply to paying customers, not to owner sessions.
	if pr.IsOwner() {
		return "", billing.Quota{}, time.Time{}, false
	}
	p, active := h.billing.ActivePlan(pr.Account.Sub)
	if !active {
		return "", billing.Quota{}, time.Time{}, false
	}
	qq, _ := billing.QuotaFor(p.Tier)
	return pr.Account.Sub, qq, p.PeriodEnd, true
}

func (h *Host) nowBilling() time.Time {
	if h != nil && h.billing != nil {
		// Service.now is unexported; wall clock is fine for enforcement.
	}
	return time.Now()
}

// checkTrafficQuota refuses when the account is already over its monthly traffic.
// Returns false when the response was already written.
func (h *Host) checkTrafficQuota(w http.ResponseWriter, pr *Principal) bool {
	acct, q, pe, ok := h.hostedAccount(pr)
	if !ok {
		return true
	}
	if err := h.billing.Usage().CheckTraffic(acct, q, h.nowBilling(), pe); err != nil {
		writeQuotaErr(w, err)
		return false
	}
	return true
}

// meterTraffic adds request+response bytes toward the monthly traffic cap.
func (h *Host) meterTraffic(pr *Principal, bytes int64) {
	acct, q, pe, ok := h.hostedAccount(pr)
	if !ok || bytes <= 0 {
		return
	}
	_ = h.billing.Usage().AddTraffic(acct, q, bytes, h.nowBilling(), pe)
}

// checkStorageQuota refuses a write that would push stored bytes past the plan cap.
// Returns false when the response was already written.
func (h *Host) checkStorageQuota(w http.ResponseWriter, pr *Principal, deltaBytes int64) bool {
	acct, q, pe, ok := h.hostedAccount(pr)
	if !ok {
		return true
	}
	if err := h.billing.Usage().CheckWrite(acct, q, deltaBytes, h.nowBilling(), pe); err != nil {
		writeQuotaErr(w, err)
		return false
	}
	return true
}

// noteStorage adds deltaBytes to the account's stored-bytes counter after a successful write.
func (h *Host) noteStorage(pr *Principal, deltaBytes int64) {
	acct, _, pe, ok := h.hostedAccount(pr)
	if !ok || deltaBytes == 0 {
		return
	}
	_ = h.billing.Usage().AddStorage(acct, deltaBytes, h.nowBilling(), pe)
}

// checkHostSwitchQuota consumes one create/drop switch for a hosted account.
// Returns false when the response was already written.
func (h *Host) checkHostSwitchQuota(w http.ResponseWriter, pr *Principal) bool {
	acct, q, pe, ok := h.hostedAccount(pr)
	if !ok {
		return true
	}
	if err := h.billing.Usage().ForceHostSwitch(acct, q, h.nowBilling(), pe); err != nil {
		writeQuotaErr(w, err)
		return false
	}
	return true
}
