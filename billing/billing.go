package billing

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Tiers are the RedX Hosted plans, cheapest first. Each has a monthly and an annual Stripe
// lookup key (Red-XAI LLC account; metadata app=redx, plan=<tier>). Annual = 10× monthly
// (2 months free). Quotas are the same for monthly and annual; they reset every month on the
// billing cycle. Bytes are GiB/TiB (1024-based).
var Tiers = []Tier{
	{"basic", "Basic", "redx_hosted_basic_monthly", "redx_hosted_basic_annual",
		Quota{TrafficBytes: 10 << 30, StorageBytes: 1 << 30, HostSwitches: 2}},
	{"bronze", "Bronze", "redx_hosted_bronze_monthly", "redx_hosted_bronze_annual",
		Quota{TrafficBytes: 50 << 30, StorageBytes: 5 << 30, HostSwitches: 5}},
	{"silver", "Silver", "redx_hosted_silver_monthly", "redx_hosted_silver_annual",
		Quota{TrafficBytes: 150 << 30, StorageBytes: 20 << 30, HostSwitches: 10}},
	{"gold", "Gold", "redx_hosted_gold_monthly", "redx_hosted_gold_annual",
		Quota{TrafficBytes: 500 << 30, StorageBytes: 50 << 30, HostSwitches: 20}},
	{"platinum", "Platinum", "redx_hosted_platinum_monthly", "redx_hosted_platinum_annual",
		Quota{TrafficBytes: 1 << 40, StorageBytes: 100 << 30, HostSwitches: 40}},
	{"emerald", "Emerald", "redx_hosted_emerald_monthly", "redx_hosted_emerald_annual",
		Quota{TrafficBytes: 5 << 40, StorageBytes: 500 << 30, HostSwitches: UnlimitedSwitches}},
}

// App is the metadata.app value on RedX's Stripe objects; other apps on the same account are ignored.
const App = "redx"

// Tier is one RedX Hosted plan (monthly + annual Stripe prices, shared monthly quotas).
type Tier struct {
	Key, Name, MonthlyLookup, AnnualLookup string
	Quota                                  Quota
}

func tierOf(key string) (Tier, bool) {
	for _, t := range Tiers {
		if t.Key == key {
			return t, true
		}
	}
	return Tier{}, false
}

// tierByLookup maps a Stripe price lookup key to the tier and interval ("month" | "year").
func tierByLookup(lk string) (Tier, string, bool) {
	for _, t := range Tiers {
		if t.MonthlyLookup == lk {
			return t, "month", true
		}
		if t.AnnualLookup == lk {
			return t, "year", true
		}
	}
	return Tier{}, "", false
}

func (t Tier) lookup(interval string) string {
	if interval == "year" {
		return t.AnnualLookup
	}
	return t.MonthlyLookup
}

// Config wires billing. Enabled needs a secret key, a publishable key and the public console URL.
type Config struct {
	SecretKey      string // STRIPE_SECRET_KEY
	PublishableKey string // STRIPE_PUBLISHABLE_KEY
	WebhookSecret  string // STRIPE_WEBHOOK_SECRET
	PortalConfig   string // STRIPE_PORTAL_CONFIG (bpc_…), optional
	PublicURL      string // https://… where this console is reached (return URL for Checkout)
	AllowLive      bool   // REDX_STRIPE_LIVE=1: live keys are refused without it
}

// ConfigFromEnv reads the Stripe settings from the environment; publicURL comes from redxd's config.
func ConfigFromEnv(publicURL string) Config {
	return Config{
		SecretKey:      os.Getenv("STRIPE_SECRET_KEY"),
		PublishableKey: os.Getenv("STRIPE_PUBLISHABLE_KEY"),
		WebhookSecret:  os.Getenv("STRIPE_WEBHOOK_SECRET"),
		PortalConfig:   os.Getenv("STRIPE_PORTAL_CONFIG"),
		PublicURL:      publicURL,
		AllowLive:      os.Getenv("REDX_STRIPE_LIVE") == "1",
	}
}

// Identity is the signed-in Red-XAI Account making a request.
type Identity struct{ Sub, Email string }

// Service is RedX Hosted billing.
type Service struct {
	cfg    Config
	stripe Stripe
	store  *Store
	usage  *UsageStore
	now    func() time.Time
	logf   func(string, ...interface{})
	reason string // why billing is off ("" when on)
}

// New builds the service. With missing or mismatched keys it still answers (plans list, 503 on
// checkout) and Reason says why; it never fails redxd start-up. usage may be nil (quotas off).
func New(cfg Config, st Stripe, store *Store, logf func(string, ...interface{})) *Service {
	return NewWithUsage(cfg, st, store, nil, logf)
}

// NewWithUsage is New plus a usage store for hosted quotas.
func NewWithUsage(cfg Config, st Stripe, store *Store, usage *UsageStore, logf func(string, ...interface{})) *Service {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	if usage == nil {
		usage, _ = OpenUsageStore("")
	}
	s := &Service{cfg: cfg, stripe: st, store: store, usage: usage, now: time.Now, logf: logf}
	live := strings.HasPrefix(cfg.SecretKey, "sk_live_") || strings.HasPrefix(cfg.SecretKey, "rk_live_")
	switch {
	case cfg.SecretKey == "" || st == nil:
		s.reason = "STRIPE_SECRET_KEY is not set"
	case cfg.PublishableKey == "":
		s.reason = "STRIPE_PUBLISHABLE_KEY is not set"
	case live != strings.HasPrefix(cfg.PublishableKey, "pk_live_"):
		s.reason = "STRIPE_PUBLISHABLE_KEY and STRIPE_SECRET_KEY are different modes"
	case live && !cfg.AllowLive:
		s.reason = "live Stripe key refused (set REDX_STRIPE_LIVE=1)"
	case !strings.HasPrefix(cfg.PublicURL, "https://") && !strings.HasPrefix(cfg.PublicURL, "http://127.0.0.1") && !strings.HasPrefix(cfg.PublicURL, "http://localhost"):
		s.reason = "public_url is not set"
	}
	if s.reason != "" {
		logf("billing off: %s", s.reason)
	}
	return s
}

// Enabled reports whether checkout works; Reason says why not.
func (s *Service) Enabled() bool  { return s.reason == "" }
func (s *Service) Reason() string { return s.reason }

// PlanFor returns the account's tier key while it is paid up ("" = no hosted plan). Quotas key off this.
func (s *Service) PlanFor(account string) string {
	p, ok := s.store.Get(account)
	if ok && p.Active(s.now()) {
		return p.Tier
	}
	return ""
}

// ActivePlan returns the paid-up plan row (and whether it is active).
func (s *Service) ActivePlan(account string) (Plan, bool) {
	p, ok := s.store.Get(account)
	if !ok || !p.Active(s.now()) {
		return Plan{}, false
	}
	return p, true
}

// Usage returns the usage store (never nil after New).
func (s *Service) Usage() *UsageStore { return s.usage }

// UsageStatusFor returns quota + usage for a paid-up account (ok false if none).
func (s *Service) UsageStatusFor(account string) (UsageStatus, bool) {
	p, ok := s.ActivePlan(account)
	if !ok {
		return UsageStatus{}, false
	}
	q, _ := QuotaFor(p.Tier)
	return s.usage.Status(account, p.Tier, p.Interval, q, s.now(), p.PeriodEnd), true
}

type price struct {
	ID         string `json:"id"`
	LookupKey  string `json:"lookup_key"`
	UnitAmount int64  `json:"unit_amount"`
	Currency   string `json:"currency"`
	Recurring  *struct {
		Interval string `json:"interval"`
	} `json:"recurring"`
}

// priceKey is "tier|interval", e.g. "gold|month".
func priceKey(tier, interval string) string { return tier + "|" + interval }

func (s *Service) prices(ctx context.Context) (map[string]price, error) {
	q := url.Values{"active": {"true"}, "limit": {"100"}}
	i := 0
	for _, t := range Tiers {
		q.Set("lookup_keys["+strconv.Itoa(i)+"]", t.MonthlyLookup)
		i++
		q.Set("lookup_keys["+strconv.Itoa(i)+"]", t.AnnualLookup)
		i++
	}
	var out struct {
		Data []price `json:"data"`
	}
	if err := s.stripe.Do(ctx, "GET", "/v1/prices", q, "", &out); err != nil {
		return nil, err
	}
	m := map[string]price{}
	for _, p := range out.Data {
		if t, iv, ok := tierByLookup(p.LookupKey); ok {
			m[priceKey(t.Key, iv)] = p
		}
	}
	return m, nil
}

// ---- HTTP ----

// Handler serves /v1/billing/*. identify returns the signed-in Red-XAI Account (or an error, already
// written to w when write is true).
func (s *Service) Handler(identify func(w http.ResponseWriter, r *http.Request) (Identity, bool)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/billing/"), "/")
		switch {
		case rest == "webhook" && r.Method == "POST":
			s.webhook(w, r)
		case rest == "plans" && r.Method == "GET":
			s.plansRoute(w, r)
		case rest == "checkout" && r.Method == "POST":
			if id, ok := identify(w, r); ok {
				s.checkoutRoute(w, r, id)
			}
		case strings.HasPrefix(rest, "checkout/") && r.Method == "GET":
			if id, ok := identify(w, r); ok {
				s.statusRoute(w, r, id, strings.TrimPrefix(rest, "checkout/"))
			}
		case rest == "me" && r.Method == "GET":
			if id, ok := identify(w, r); ok {
				s.meRoute(w, id)
			}
		case rest == "portal" && r.Method == "POST":
			if id, ok := identify(w, r); ok {
				s.portalRoute(w, r, id)
			}
		case rest == "hosting" && r.Method == "POST":
			if id, ok := identify(w, r); ok {
				s.hostingRoute(w, r, id)
			}
		default:
			jerr(w, 404, "not_found", "not found")
		}
	})
}

func jout(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func jerr(w http.ResponseWriter, code int, errCode, msg string) {
	jout(w, code, map[string]string{"error": errCode, "message": msg})
}

func readBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		jerr(w, 415, "bad_request", "content type must be application/json")
		return false
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(v); err != nil {
		jerr(w, 400, "bad_request", "invalid JSON")
		return false
	}
	return true
}

func (s *Service) stripeErr(w http.ResponseWriter, err error) {
	s.logf("billing: %v", err)
	jerr(w, 502, "stripe_error", "the payment service did not answer; try again")
}

func (s *Service) plansRoute(w http.ResponseWriter, r *http.Request) {
	type planOut struct {
		Key       string `json:"key"`
		Name      string `json:"name"`
		Amount    int64  `json:"amount,omitempty"`
		Currency  string `json:"currency,omitempty"`
		Interval  string `json:"interval,omitempty"`
		Available bool   `json:"available"`
		Quota     Quota  `json:"quota"`
	}
	out := map[string]interface{}{"enabled": s.Enabled()}
	plans := make([]planOut, 0, len(Tiers)*2)
	var ps map[string]price
	if s.Enabled() {
		var err error
		if ps, err = s.prices(r.Context()); err != nil {
			s.stripeErr(w, err)
			return
		}
		out["publishableKey"] = s.cfg.PublishableKey
	} else {
		out["reason"] = s.reason
	}
	for _, t := range Tiers {
		for _, iv := range []string{"month", "year"} {
			po := planOut{Key: t.Key, Name: t.Name, Interval: iv, Quota: t.Quota}
			if p, ok := ps[priceKey(t.Key, iv)]; ok {
				po.Amount, po.Currency, po.Available = p.UnitAmount, p.Currency, true
				if p.Recurring != nil && p.Recurring.Interval != "" {
					po.Interval = p.Recurring.Interval
				}
			}
			plans = append(plans, po)
		}
	}
	out["plans"] = plans
	jout(w, 200, out)
}

var idemRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,80}$`)

func (s *Service) checkoutRoute(w http.ResponseWriter, r *http.Request, id Identity) {
	if !s.Enabled() {
		jerr(w, 503, "billing_off", s.reason)
		return
	}
	var in struct {
		Plan           string `json:"plan"`
		Interval       string `json:"interval"` // month (default) | year
		IdempotencyKey string `json:"idempotencyKey"`
	}
	if !readBody(w, r, &in) {
		return
	}
	t, ok := tierOf(in.Plan)
	if !ok {
		jerr(w, 400, "bad_plan", "unknown plan")
		return
	}
	iv := in.Interval
	if iv == "" || iv == "monthly" {
		iv = "month"
	}
	if iv == "annual" || iv == "yearly" {
		iv = "year"
	}
	if iv != "month" && iv != "year" {
		jerr(w, 400, "bad_interval", "interval must be month or year")
		return
	}
	if !idemRe.MatchString(in.IdempotencyKey) {
		jerr(w, 400, "bad_request", "idempotencyKey must be 8-80 letters, digits, - or _")
		return
	}
	cur, have := s.store.Get(id.Sub)
	if have && cur.Active(s.now()) && cur.Subscription != "" {
		// One subscription per account: switching tiers happens in the portal (prorated by Stripe).
		jerr(w, 409, "manage_in_portal", "you already have RedX Hosted "+cur.Tier+"; change plan in Manage billing")
		return
	}
	ps, err := s.prices(r.Context())
	if err != nil {
		s.stripeErr(w, err)
		return
	}
	p, ok := ps[priceKey(t.Key, iv)]
	if !ok {
		jerr(w, 503, "plan_unavailable", "this plan is not on sale yet")
		return
	}
	f := url.Values{}
	f.Set("mode", "subscription")
	f.Set("ui_mode", "elements")
	f.Set("line_items[0][price]", p.ID)
	f.Set("line_items[0][quantity]", "1")
	f.Set("client_reference_id", id.Sub)
	f.Set("return_url", strings.TrimRight(s.cfg.PublicURL, "/")+"/ui/billing.html?return=1&session_id={CHECKOUT_SESSION_ID}")
	if have && cur.Customer != "" {
		f.Set("customer", cur.Customer)
	} else if id.Email != "" {
		f.Set("customer_email", id.Email)
	}
	for k, v := range map[string]string{"app": App, "plan": t.Key, "interval": iv, "account": id.Sub} {
		f.Set("metadata["+k+"]", v)
		f.Set("subscription_data[metadata]["+k+"]", v)
	}
	var sess struct {
		ID           string `json:"id"`
		ClientSecret string `json:"client_secret"`
	}
	idem := "redx-checkout-"+id.Sub+"-"+iv+"-"+in.IdempotencyKey
	if err := s.stripe.Do(r.Context(), "POST", "/v1/checkout/sessions", f, idem, &sess); err != nil {
		s.stripeErr(w, err)
		return
	}
	jout(w, 200, map[string]interface{}{"session": sess.ID, "clientSecret": sess.ClientSecret,
		"publishableKey": s.cfg.PublishableKey, "plan": t.Key, "interval": iv, "amount": p.UnitAmount, "currency": p.Currency})
}

var sessRe = regexp.MustCompile(`^cs_(test|live)_[A-Za-z0-9]{10,200}$`)

func (s *Service) statusRoute(w http.ResponseWriter, r *http.Request, id Identity, sid string) {
	if !s.Enabled() {
		jerr(w, 503, "billing_off", s.reason)
		return
	}
	if !sessRe.MatchString(sid) {
		jerr(w, 400, "bad_request", "bad session id")
		return
	}
	var sess struct {
		Status            string            `json:"status"`
		PaymentStatus     string            `json:"payment_status"`
		ClientReferenceID string            `json:"client_reference_id"`
		Subscription      json.RawMessage   `json:"subscription"`
		Metadata          map[string]string `json:"metadata"`
	}
	if err := s.stripe.Do(r.Context(), "GET", "/v1/checkout/sessions/"+sid, nil, "", &sess); err != nil {
		s.stripeErr(w, err)
		return
	}
	if sess.ClientReferenceID != id.Sub || sess.Metadata["app"] != App {
		jerr(w, 404, "not_found", "checkout not found")
		return
	}
	// Grant straight away if the webhook has not arrived yet (it re-reads the same subscription).
	if sub := idOf(sess.Subscription); sub != "" && sess.Status == "complete" {
		if err := s.syncSubscription(r.Context(), sub); err != nil {
			s.logf("billing: sync on return: %v", err)
		}
	}
	p, _ := s.store.Get(id.Sub)
	jout(w, 200, map[string]interface{}{"status": sess.Status, "paymentStatus": sess.PaymentStatus, "payment": sess.PaymentStatus,
		"plan": sess.Metadata["plan"], "active": p.Active(s.now()) && p.Tier == sess.Metadata["plan"]})
}

func (s *Service) meRoute(w http.ResponseWriter, id Identity) {
	p, _ := s.store.Get(id.Sub)
	out := map[string]interface{}{"enabled": s.Enabled(), "plan": "", "active": false}
	if p.Active(s.now()) {
		out["plan"], out["active"], out["status"], out["cancelAtPeriodEnd"] = p.Tier, true, p.Status, p.CancelAtEnd
		out["interval"] = p.Interval
		if p.Interval == "" {
			out["interval"] = "month"
		}
		if !p.PeriodEnd.IsZero() {
			out["periodEnd"] = p.PeriodEnd
		}
		if q, ok := QuotaFor(p.Tier); ok {
			out["quota"] = q
			out["usage"] = s.usage.Status(id.Sub, p.Tier, p.Interval, q, s.now(), p.PeriodEnd)
		}
	}
	out["portal"] = p.Customer != ""
	jout(w, 200, out)
}

func (s *Service) portalRoute(w http.ResponseWriter, r *http.Request, id Identity) {
	if !s.Enabled() {
		jerr(w, 503, "billing_off", s.reason)
		return
	}
	p, _ := s.store.Get(id.Sub)
	if p.Customer == "" {
		jerr(w, 404, "no_billing", "no RedX Hosted billing for this account yet")
		return
	}
	f := url.Values{"customer": {p.Customer}, "return_url": {strings.TrimRight(s.cfg.PublicURL, "/") + "/ui/billing.html"}}
	if s.cfg.PortalConfig != "" {
		f.Set("configuration", s.cfg.PortalConfig)
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := s.stripe.Do(r.Context(), "POST", "/v1/billing_portal/sessions", f, "", &out); err != nil {
		s.stripeErr(w, err)
		return
	}
	jout(w, 200, map[string]string{"url": out.URL})
}

// hostingRoute turns RedX Hosted on or off for the signed-in account (counts toward the monthly switch budget).
func (s *Service) hostingRoute(w http.ResponseWriter, r *http.Request, id Identity) {
	p, ok := s.ActivePlan(id.Sub)
	if !ok {
		jerr(w, 402, "plan_required", "Choose a RedX Hosted plan first")
		return
	}
	var in struct {
		Action string `json:"action"` // on | off
	}
	if !readBody(w, r, &in) {
		return
	}
	wantOn := false
	switch strings.ToLower(in.Action) {
	case "on", "start":
		wantOn = true
	case "off", "stop":
		wantOn = false
	default:
		jerr(w, 400, "bad_request", "action must be on or off")
		return
	}
	q, _ := QuotaFor(p.Tier)
	if err := s.usage.TryHostSwitch(id.Sub, q, wantOn, s.now(), p.PeriodEnd); err != nil {
		var qe *ErrQuota
		if errors.As(err, &qe) {
			jout(w, qe.HTTP, map[string]string{"error": qe.Code, "message": qe.Message, "upgrade": "/ui/billing.html"})
			return
		}
		jerr(w, 500, "error", err.Error())
		return
	}
	st := s.usage.Status(id.Sub, p.Tier, p.Interval, q, s.now(), p.PeriodEnd)
	jout(w, 200, map[string]interface{}{"ok": true, "hostedOn": st.HostedOn, "usage": st})
}

// ---- webhook ----

func (s *Service) webhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		jerr(w, 400, "bad_request", "unreadable body")
		return
	}
	if s.cfg.WebhookSecret == "" || s.stripe == nil {
		jerr(w, 503, "billing_off", "STRIPE_WEBHOOK_SECRET is not set")
		return
	}
	if VerifySignature(body, r.Header.Get("Stripe-Signature"), s.cfg.WebhookSecret, s.now(), 5*time.Minute) != nil {
		jerr(w, 400, "bad_signature", "signature does not verify")
		return
	}
	var ev struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Livemode bool   `json:"livemode"`
		Data     struct {
			Object json.RawMessage `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &ev); err != nil || ev.ID == "" {
		jerr(w, 400, "bad_request", "not a Stripe event")
		return
	}
	live := strings.HasPrefix(s.cfg.SecretKey, "sk_live_") || strings.HasPrefix(s.cfg.SecretKey, "rk_live_")
	if ev.Livemode != live {
		jerr(w, 400, "wrong_mode", "event mode does not match this server's key")
		return
	}
	if s.store.seen(ev.ID) {
		jout(w, 200, map[string]bool{"received": true, "duplicate": true})
		return
	}
	if err := s.handleEvent(r.Context(), ev.Type, ev.Data.Object); err != nil {
		s.store.forget(ev.ID) // let Stripe retry
		s.logf("billing: webhook %s: %v", ev.Type, err)
		jerr(w, 500, "retry", "could not process the event")
		return
	}
	jout(w, 200, map[string]bool{"received": true})
}

func idOf(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &o)
	return o.ID
}

func (s *Service) handleEvent(ctx context.Context, typ string, obj json.RawMessage) error {
	switch typ {
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted",
		"customer.subscription.paused", "customer.subscription.resumed":
		var o struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(obj, &o)
		return s.syncSubscription(ctx, o.ID)
	case "invoice.paid", "invoice.payment_succeeded", "invoice.payment_failed":
		var inv struct {
			Subscription json.RawMessage `json:"subscription"`
			Parent       struct {
				SubscriptionDetails struct {
					Subscription json.RawMessage `json:"subscription"`
				} `json:"subscription_details"`
			} `json:"parent"`
		}
		_ = json.Unmarshal(obj, &inv)
		sub := idOf(inv.Parent.SubscriptionDetails.Subscription)
		if sub == "" {
			sub = idOf(inv.Subscription)
		}
		if sub == "" {
			return nil // not a subscription invoice
		}
		return s.syncSubscription(ctx, sub)
	case "checkout.session.completed":
		var cs struct {
			Mode         string            `json:"mode"`
			Subscription json.RawMessage   `json:"subscription"`
			Metadata     map[string]string `json:"metadata"`
		}
		_ = json.Unmarshal(obj, &cs)
		if cs.Metadata["app"] != App || cs.Mode != "subscription" {
			return nil
		}
		if sub := idOf(cs.Subscription); sub != "" {
			return s.syncSubscription(ctx, sub)
		}
	}
	return nil
}

type stripeSub struct {
	ID                string            `json:"id"`
	Status            string            `json:"status"`
	Customer          json.RawMessage   `json:"customer"`
	CancelAtPeriodEnd bool              `json:"cancel_at_period_end"`
	CurrentPeriodEnd  int64             `json:"current_period_end"`
	Metadata          map[string]string `json:"metadata"`
	Items             struct {
		Data []struct {
			CurrentPeriodEnd int64 `json:"current_period_end"`
			Price            struct {
				LookupKey string `json:"lookup_key"`
			} `json:"price"`
		} `json:"data"`
	} `json:"items"`
}

// syncSubscription re-reads a subscription from Stripe (never trusting the event body) and sets the
// account's plan from it: the tier comes from the price's lookup key, access runs to the paid period end.
func (s *Service) syncSubscription(ctx context.Context, id string) error {
	if !strings.HasPrefix(id, "sub_") {
		return errors.New("bad subscription id")
	}
	var sub stripeSub
	if err := s.stripe.Do(ctx, "GET", "/v1/subscriptions/"+id, nil, "", &sub); err != nil {
		var se *Error
		if errors.As(err, &se) && se.Status == 404 {
			return nil
		}
		return err
	}
	if sub.Metadata["app"] != App {
		return nil // another app on the same Stripe account (e.g. Rotten Apple)
	}
	account := sub.Metadata["account"]
	if account == "" {
		return nil
	}
	tier, interval, end := "", "", sub.CurrentPeriodEnd
	for _, it := range sub.Items.Data {
		if t, iv, ok := tierByLookup(it.Price.LookupKey); ok {
			tier, interval = t.Key, iv
			if it.CurrentPeriodEnd > end {
				end = it.CurrentPeriodEnd
			}
		}
	}
	if interval == "" {
		if sub.Metadata["interval"] == "year" {
			interval = "year"
		} else if tier != "" {
			interval = "month"
		}
	}
	prev, _ := s.store.Get(account)
	if prev.Subscription != "" && prev.Subscription != sub.ID && prev.Active(s.now()) && sub.Status != "active" && sub.Status != "trialing" {
		return nil // an old, ended subscription must not knock out the current one
	}
	p := Plan{Account: account, Tier: tier, Interval: interval, Status: sub.Status, CancelAtEnd: sub.CancelAtPeriodEnd,
		Customer: idOf(sub.Customer), Subscription: sub.ID, Updated: s.now().UTC()}
	if end > 0 {
		p.PeriodEnd = time.Unix(end, 0).UTC()
	}
	if p.Customer == "" {
		p.Customer = prev.Customer
	}
	s.logf("billing: account %s plan %s status %s", account, tier, sub.Status)
	return s.store.Put(p)
}
