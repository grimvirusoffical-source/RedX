package host

import (
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"redx/billing"
)

// RedX Hosted plans on Stripe Billing (package billing): /v1/billing/plans (public), /v1/billing/checkout,
// /v1/billing/checkout/{session}, /v1/billing/me, /v1/billing/portal (signed-in Red-XAI Account) and
// /v1/billing/webhook (Stripe, signature-checked). The console page is /ui/billing.html.

func newBilling(cfg Config, logf func(string, ...interface{})) (*billing.Service, error) {
	bc := billing.ConfigFromEnv(cfg.BillingPublicURL)
	if bc.PublicURL == "" {
		bc.PublicURL = cfg.Advertise
	}
	st, err := billing.OpenStore(filepath.Join(cfg.DataDir, "billing", "plans.json"))
	if err != nil {
		return nil, err
	}
	us, err := billing.OpenUsageStore(filepath.Join(cfg.DataDir, "billing", "usage.json"))
	if err != nil {
		return nil, err
	}
	var sc billing.Stripe
	if bc.SecretKey != "" {
		sc = billing.NewClient(bc.SecretKey)
	}
	return billing.NewWithUsage(bc, sc, st, us, logf), nil
}

// BillingPlan returns the RedX Hosted tier a Red-XAI Account is paid up on ("" = none).
// Quotas (storage, traffic, host switches) key off this; see docs/billing.md.
func (h *Host) BillingPlan(accountSub string) string {
	if h.billing == nil {
		return ""
	}
	return h.billing.PlanFor(accountSub)
}

// BillingUsage returns quota + usage for a paid-up account.
func (h *Host) BillingUsage(accountSub string) (billing.UsageStatus, bool) {
	if h.billing == nil {
		return billing.UsageStatus{}, false
	}
	return h.billing.UsageStatusFor(accountSub)
}

func (h *Host) billingRoute(w http.ResponseWriter, r *http.Request) {
	if h.billing == nil {
		writeAPIErr(w, 404, "not found", "billing_off", "Billing is not enabled on this server.")
		return
	}
	h.billing.Handler(func(w http.ResponseWriter, r *http.Request) (billing.Identity, bool) {
		pr, wait, err := h.Auth.Authenticate(r)
		switch {
		case errors.Is(err, ErrThrottled):
			w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
			writeAPIErr(w, http.StatusTooManyRequests, "rate limit exceeded", "rate_limited", "Too many requests. Wait a moment and try again.")
			return billing.Identity{}, false
		case err != nil:
			h.authBad.Add(1)
			w.Header().Set("WWW-Authenticate", `Bearer realm="redx"`)
			writeAPIErr(w, http.StatusUnauthorized, "unauthorized", "unauthorized", "Sign in, or send a valid API key, to use billing.")
			return billing.Identity{}, false
		}
		if pr.Account == nil || pr.Account.Sub == "" {
			acctErr(w, 403, "account_required", "Sign in with your Red-XAI Account to manage RedX Hosted plans.")
			return billing.Identity{}, false
		}
		return billing.Identity{Sub: pr.Account.Sub, Email: pr.Account.Email}, true
	}).ServeHTTP(w, r)
}
