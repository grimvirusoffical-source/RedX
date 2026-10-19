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
	noteReason(w, "quota_exceeded")
	writeJSON(w, qe.HTTP, map[string]string{
		"error": qe.Code, "code": "quota_exceeded", "limit": qe.Code, "message": qe.Message, "upgrade": "/ui/billing.html",
	})
	return true
}

// hostedAccount returns the Red-XAI Account sub for quota enforcement.
// Owners and host-admin keys are not capped. A self-hosted key (no Owner) is
// not capped. A tenant session or a tenant API key is capped from the stored
// plan row even when that plan is past_due, canceled or past grace: an inactive
// plan is enforced, never treated as "no account" (which would skip the cap).
func (h *Host) hostedAccount(pr *Principal) (account string, q billing.Quota, periodEnd time.Time, ok bool) {
	if h == nil || h.billing == nil || pr == nil || pr.IsOwner() || pr.Key.IsHostAdmin() {
		return "", billing.Quota{}, time.Time{}, false
	}
	acct := pr.tenantSub()
	if acct == "" {
		return "", billing.Quota{}, time.Time{}, false
	}
	p, found := h.billing.StoredPlan(acct)
	if !found || p.Tier == "" {
		return "", billing.Quota{}, time.Time{}, false
	}
	qq, qok := billing.QuotaFor(p.Tier)
	if !qok {
		return "", billing.Quota{}, time.Time{}, false
	}
	return acct, qq, p.PeriodEnd, true
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
	if deltaBytes < 0 {
		deltaBytes = 0
	}
	// The cap is the bytes on disk for this account's databases, not a counter
	// that only increments. A write that would pass the tier's storage limit is refused.
	measured := h.accountStorage(acct)
	_ = h.billing.Usage().SetStorage(acct, measured, h.nowBilling(), pe)
	if q.StorageBytes > 0 && deltaBytes > 0 && measured+deltaBytes > q.StorageBytes {
		writeQuotaErr(w, errStorageQuota())
		return false
	}
	return true
}

func errStorageQuota() error {
	return &billing.ErrQuota{Code: "storage_quota", HTTP: http.StatusPaymentRequired,
		Message: "This write would go past your RedX Hosted storage limit. Upgrade your plan at /ui/billing.html."}
}

// noteStorage adds deltaBytes to the account's stored-bytes counter after a successful write.
func (h *Host) noteStorage(pr *Principal, deltaBytes int64) {
	acct, _, pe, ok := h.hostedAccount(pr)
	if !ok {
		return
	}
	_ = deltaBytes
	_ = h.billing.Usage().SetStorage(acct, h.accountStorage(acct), h.nowBilling(), pe)
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
