package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStripe answers the few endpoints billing calls, from in-memory state.
type fakeStripe struct {
	mu       sync.Mutex
	prices   []price
	subs     map[string]map[string]interface{}
	sessions map[string]map[string]interface{}
	posts    []url.Values
	idem     map[string]string
}

func newFake() *fakeStripe {
	f := &fakeStripe{subs: map[string]map[string]interface{}{}, sessions: map[string]map[string]interface{}{}, idem: map[string]string{}}
	amtM := map[string]int64{"basic": 2000, "bronze": 4500, "silver": 6000, "gold": 8000, "platinum": 9000, "emerald": 10000}
	amtY := map[string]int64{"basic": 20000, "bronze": 45000, "silver": 60000, "gold": 80000, "platinum": 90000, "emerald": 100000}
	for _, t := range Tiers {
		pm := price{ID: "price_" + t.Key + "_month", LookupKey: t.MonthlyLookup, UnitAmount: amtM[t.Key], Currency: "usd"}
		pm.Recurring = &struct {
			Interval string `json:"interval"`
		}{"month"}
		py := price{ID: "price_" + t.Key + "_year", LookupKey: t.AnnualLookup, UnitAmount: amtY[t.Key], Currency: "usd"}
		py.Recurring = &struct {
			Interval string `json:"interval"`
		}{"year"}
		f.prices = append(f.prices, pm, py)
	}
	return f
}

func (f *fakeStripe) Do(_ context.Context, method, path string, form url.Values, idem string, out interface{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var v interface{}
	switch {
	case method == "GET" && path == "/v1/prices":
		var data []price
		for _, p := range f.prices {
			for k, vs := range form {
				if strings.HasPrefix(k, "lookup_keys[") && vs[0] == p.LookupKey {
					data = append(data, p)
				}
			}
		}
		v = map[string]interface{}{"data": data}
	case method == "POST" && path == "/v1/checkout/sessions":
		if id, ok := f.idem[idem]; ok {
			v = f.sessions[id]
			break
		}
		f.posts = append(f.posts, form)
		id := "cs_test_" + strings.Repeat("a", 10) + string(rune('a'+len(f.sessions)))
		f.idem[idem] = id
		meta := map[string]string{}
		for k, vs := range form {
			if strings.HasPrefix(k, "metadata[") {
				meta[strings.TrimSuffix(strings.TrimPrefix(k, "metadata["), "]")] = vs[0]
			}
		}
		f.sessions[id] = map[string]interface{}{"id": id, "client_secret": id + "_secret_x", "status": "open",
			"client_reference_id": form.Get("client_reference_id"), "metadata": meta, "subscription": nil}
		v = f.sessions[id]
	case method == "GET" && strings.HasPrefix(path, "/v1/checkout/sessions/"):
		s, ok := f.sessions[strings.TrimPrefix(path, "/v1/checkout/sessions/")]
		if !ok {
			return &Error{Status: 404, Code: "resource_missing"}
		}
		v = s
	case method == "GET" && strings.HasPrefix(path, "/v1/subscriptions/"):
		s, ok := f.subs[strings.TrimPrefix(path, "/v1/subscriptions/")]
		if !ok {
			return &Error{Status: 404, Code: "resource_missing"}
		}
		v = s
	case method == "POST" && path == "/v1/billing_portal/sessions":
		f.posts = append(f.posts, form)
		v = map[string]string{"url": "https://billing.stripe.com/p/session/test_x"}
	default:
		return &Error{Status: 400, Message: "fake: unhandled " + method + " " + path}
	}
	b, _ := json.Marshal(v)
	return json.Unmarshal(b, out)
}

// pay completes a session the way Stripe would: a subscription on the session's price.
func (f *fakeStripe) pay(sessID, subID, tier string, end time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sessions[sessID]
	meta := s["metadata"].(map[string]string)
	s["status"], s["payment_status"], s["subscription"] = "complete", "paid", subID
	f.setSubLocked(subID, "active", tier, meta["account"], end)
}

func (f *fakeStripe) setSub(id, status, tier, account string, end time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setSubLocked(id, status, tier, account, end)
}

func (f *fakeStripe) setSubLocked(id, status, tier, account string, end time.Time) {
	f.setSubIntervalLocked(id, status, tier, "month", account, end)
}

func (f *fakeStripe) setSubIntervalLocked(id, status, tier, interval, account string, end time.Time) {
	t, _ := tierOf(tier)
	lk := t.MonthlyLookup
	if interval == "year" {
		lk = t.AnnualLookup
	}
	f.subs[id] = map[string]interface{}{"id": id, "status": status, "customer": "cus_test_1",
		"metadata": map[string]string{"app": App, "plan": tier, "interval": interval, "account": account},
		"items": map[string]interface{}{"data": []interface{}{map[string]interface{}{
			"current_period_end": end.Unix(), "price": map[string]string{"lookup_key": lk}}}}}
}

func (f *fakeStripe) payInterval(sessID, subID, tier, interval string, end time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sessions[sessID]
	meta := s["metadata"].(map[string]string)
	s["status"], s["payment_status"], s["subscription"] = "complete", "paid", subID
	f.setSubIntervalLocked(subID, "active", tier, interval, meta["account"], end)
}

const whsec = "whsec_test_fake"

func testService(t *testing.T) (*Service, *fakeStripe, http.Handler) {
	f := newFake()
	st, _ := OpenStore("")
	s := New(Config{SecretKey: "sk_test_fake", PublishableKey: "pk_test_fake", WebhookSecret: whsec,
		PortalConfig: "bpc_test", PublicURL: "https://redx.example"}, f, st, t.Logf)
	if !s.Enabled() {
		t.Fatalf("billing off: %s", s.Reason())
	}
	ident := func(w http.ResponseWriter, r *http.Request) (Identity, bool) {
		sub := r.Header.Get("X-Test-Account")
		if sub == "" {
			jerr(w, 401, "unauthorized", "sign in")
			return Identity{}, false
		}
		return Identity{Sub: sub, Email: sub + "@example.com"}, true
	}
	return s, f, s.Handler(ident)
}

func call(t *testing.T, h http.Handler, method, path, acct string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, rd)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if acct != "" {
		r.Header.Set("X-Test-Account", acct)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func hook(t *testing.T, h http.Handler, id, typ string, obj interface{}, secret string) int {
	t.Helper()
	b, _ := json.Marshal(map[string]interface{}{"id": id, "type": typ, "livemode": false, "data": map[string]interface{}{"object": obj}})
	r := httptest.NewRequest("POST", "/v1/billing/webhook", bytes.NewReader(b))
	r.Header.Set("Stripe-Signature", Sign(b, secret, time.Now()))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestHostedCheckoutAndWebhooks(t *testing.T) {
	s, f, h := testService(t)
	if c, out := call(t, h, "GET", "/v1/billing/plans", "", nil); c != 200 || out["publishableKey"] != "pk_test_fake" || len(out["plans"].([]interface{})) != 12 {
		t.Fatalf("plans: %d %v", c, out)
	}
	if c, _ := call(t, h, "POST", "/v1/billing/checkout", "", map[string]string{"plan": "gold", "idempotencyKey": "abcdefgh1"}); c != 401 {
		t.Fatalf("anonymous checkout: %d", c)
	}
	if c, _ := call(t, h, "POST", "/v1/billing/checkout", "acct1", map[string]string{"plan": "diamond", "idempotencyKey": "abcdefgh1"}); c != 400 {
		t.Fatalf("bad plan: %d", c)
	}
	c, out := call(t, h, "POST", "/v1/billing/checkout", "acct1", map[string]string{"plan": "gold", "idempotencyKey": "abcdefgh1"})
	if c != 200 || out["clientSecret"] == "" || out["amount"].(float64) != 8000 {
		t.Fatalf("checkout: %d %v", c, out)
	}
	form := f.posts[0]
	for k, want := range map[string]string{"mode": "subscription", "ui_mode": "elements", "line_items[0][price]": "price_gold_month",
		"client_reference_id": "acct1", "subscription_data[metadata][account]": "acct1", "subscription_data[metadata][app]": "redx",
		"return_url": "https://redx.example/ui/billing.html?return=1&session_id={CHECKOUT_SESSION_ID}"} {
		if form.Get(k) != want {
			t.Fatalf("%s = %q, want %q", k, form.Get(k), want)
		}
	}
	sess := out["session"].(string)
	// replay with the same key: same session, no second create
	if _, again := call(t, h, "POST", "/v1/billing/checkout", "acct1", map[string]string{"plan": "gold", "idempotencyKey": "abcdefgh1"}); again["session"] != sess || len(f.posts) != 1 {
		t.Fatalf("idempotent replay made a new session")
	}
	// someone else cannot read the session
	if c, _ := call(t, h, "GET", "/v1/billing/checkout/"+sess, "acct2", nil); c != 404 {
		t.Fatalf("other account read session: %d", c)
	}
	if s.PlanFor("acct1") != "" {
		t.Fatal("plan before paying")
	}

	end := time.Now().Add(30 * 24 * time.Hour)
	f.pay(sess, "sub_1", "gold", end)
	// forged signature: ignored
	if c := hook(t, h, "evt_0", "customer.subscription.created", map[string]string{"id": "sub_1"}, "whsec_wrong"); c != 400 {
		t.Fatalf("forged webhook: %d", c)
	}
	if s.PlanFor("acct1") != "" {
		t.Fatal("forged webhook granted a plan")
	}
	if c := hook(t, h, "evt_1", "customer.subscription.created", map[string]string{"id": "sub_1"}, whsec); c != 200 {
		t.Fatalf("webhook: %d", c)
	}
	if s.PlanFor("acct1") != "gold" {
		t.Fatalf("plan = %q", s.PlanFor("acct1"))
	}
	if c, st := call(t, h, "GET", "/v1/billing/checkout/"+sess, "acct1", nil); c != 200 || st["active"] != true {
		t.Fatalf("status: %d %v", c, st)
	}
	if c, _ := call(t, h, "POST", "/v1/billing/checkout", "acct1", map[string]string{"plan": "emerald", "idempotencyKey": "abcdefgh2"}); c != 409 {
		t.Fatalf("second subscription: %d", c)
	}
	// portal switch to platinum
	f.setSub("sub_1", "active", "platinum", "acct1", end)
	hook(t, h, "evt_2", "customer.subscription.updated", map[string]string{"id": "sub_1"}, whsec)
	if s.PlanFor("acct1") != "platinum" {
		t.Fatalf("after switch: %q", s.PlanFor("acct1"))
	}
	// renewal failed: past_due keeps access to the period end + grace
	f.setSub("sub_1", "past_due", "platinum", "acct1", end)
	hook(t, h, "evt_3", "invoice.payment_failed", map[string]interface{}{"parent": map[string]interface{}{"subscription_details": map[string]string{"subscription": "sub_1"}}}, whsec)
	if s.PlanFor("acct1") != "platinum" {
		t.Fatal("past_due should keep access until the period ends")
	}
	// renewal paid: new period
	end2 := end.Add(30 * 24 * time.Hour)
	f.setSub("sub_1", "active", "platinum", "acct1", end2)
	hook(t, h, "evt_4", "invoice.paid", map[string]interface{}{"subscription": "sub_1"}, whsec)
	p, _ := s.store.Get("acct1")
	if !p.PeriodEnd.Equal(time.Unix(end2.Unix(), 0).UTC()) || p.Customer != "cus_test_1" {
		t.Fatalf("after renewal: %+v", p)
	}
	// portal
	if c, po := call(t, h, "POST", "/v1/billing/portal", "acct1", map[string]string{}); c != 200 || !strings.HasPrefix(po["url"].(string), "https://billing.stripe.com/") {
		t.Fatalf("portal: %d %v", c, po)
	}
	if f.posts[len(f.posts)-1].Get("configuration") != "bpc_test" || f.posts[len(f.posts)-1].Get("customer") != "cus_test_1" {
		t.Fatal("portal form")
	}
	// duplicate event: no-op
	if c := hook(t, h, "evt_4", "invoice.paid", map[string]interface{}{"subscription": "sub_1"}, whsec); c != 200 {
		t.Fatal("dup")
	}
	// canceled: revoked
	f.setSub("sub_1", "canceled", "platinum", "acct1", end2)
	hook(t, h, "evt_5", "customer.subscription.deleted", map[string]string{"id": "sub_1"}, whsec)
	if s.PlanFor("acct1") != "" {
		t.Fatal("canceled subscription still grants")
	}
	// period long over: even active status no longer grants
	s.now = func() time.Time { return end2.Add(Grace + time.Hour) }
	f.setSub("sub_1", "active", "platinum", "acct1", end2)
	hook(t, h, "evt_6", "customer.subscription.updated", map[string]string{"id": "sub_1"}, whsec)
	if s.PlanFor("acct1") != "" {
		t.Fatal("expired period still grants")
	}
}

func TestOtherAppsAndModes(t *testing.T) {
	s, f, h := testService(t)
	f.subs["sub_ra"] = map[string]interface{}{"id": "sub_ra", "status": "active", "metadata": map[string]string{"app": "rotten-apple", "account": "acct1"}}
	hook(t, h, "evt_ra", "customer.subscription.created", map[string]string{"id": "sub_ra"}, whsec)
	if p, ok := s.store.Get("acct1"); ok {
		t.Fatalf("Rotten Apple subscription touched RedX plans: %+v", p)
	}
	b, _ := json.Marshal(map[string]interface{}{"id": "evt_live", "type": "invoice.paid", "livemode": true, "data": map[string]interface{}{"object": map[string]string{}}})
	r := httptest.NewRequest("POST", "/v1/billing/webhook", bytes.NewReader(b))
	r.Header.Set("Stripe-Signature", Sign(b, whsec, time.Now()))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("live event on a test server: %d", w.Code)
	}
	old := Sign(b, whsec, time.Now().Add(-time.Hour))
	if VerifySignature(b, old, whsec, time.Now(), 5*time.Minute) == nil {
		t.Fatal("stale signature accepted")
	}
}

func TestConfigGuards(t *testing.T) {
	st, _ := OpenStore("")
	f := newFake()
	for _, c := range []struct {
		cfg  Config
		want string
	}{
		{Config{}, "STRIPE_SECRET_KEY"},
		{Config{SecretKey: "sk_test_x", PublicURL: "https://x"}, "STRIPE_PUBLISHABLE_KEY"},
		{Config{SecretKey: "sk_live_x", PublishableKey: "pk_test_x", PublicURL: "https://x"}, "different modes"},
		{Config{SecretKey: "sk_live_x", PublishableKey: "pk_live_x", PublicURL: "https://x"}, "REDX_STRIPE_LIVE"},
		{Config{SecretKey: "sk_test_x", PublishableKey: "pk_test_x"}, "public_url"},
	} {
		s := New(c.cfg, f, st, nil)
		if s.Enabled() || !strings.Contains(s.Reason(), c.want) {
			t.Fatalf("%+v: reason %q, want %q", c.cfg, s.Reason(), c.want)
		}
		if strings.Contains(s.Reason(), "sk_") {
			t.Fatal("reason leaks a key")
		}
	}
	if s := New(Config{SecretKey: "sk_live_x", PublishableKey: "pk_live_x", PublicURL: "https://x", AllowLive: true}, f, st, nil); !s.Enabled() {
		t.Fatalf("live with the flag: %s", s.Reason())
	}
}

func TestErrorRedactsKeys(t *testing.T) {
	e := &Error{Status: 401, Message: "Invalid API Key provided: sk_live_*********abc$"}
	if strings.Contains(e.Error(), "abc") || !strings.Contains(e.Error(), "[redacted]") {
		t.Fatal(e.Error())
	}
}

func TestAnnualCheckoutAndWebhook(t *testing.T) {
	s, f, h := testService(t)
	for _, tier := range []string{"basic", "bronze", "silver", "gold", "platinum", "emerald"} {
		acct := "ann-" + tier
		c, out := call(t, h, "POST", "/v1/billing/checkout", acct, map[string]string{
			"plan": tier, "interval": "year", "idempotencyKey": "annualkey" + tier})
		wantAmt := map[string]float64{"basic": 20000, "bronze": 45000, "silver": 60000, "gold": 80000, "platinum": 90000, "emerald": 100000}[tier]
		if c != 200 || out["interval"] != "year" || out["amount"].(float64) != wantAmt {
			t.Fatalf("%s annual checkout: %d %v", tier, c, out)
		}
		form := f.posts[len(f.posts)-1]
		if form.Get("line_items[0][price]") != "price_"+tier+"_year" {
			t.Fatalf("%s price id: %s", tier, form.Get("line_items[0][price]"))
		}
		if form.Get("subscription_data[metadata][interval]") != "year" {
			t.Fatalf("%s metadata interval", tier)
		}
		sess := out["session"].(string)
		end := time.Now().Add(365 * 24 * time.Hour)
		f.payInterval(sess, "sub_ann_"+tier, tier, "year", end)
		if c := hook(t, h, "evt_ann_"+tier, "customer.subscription.created", map[string]string{"id": "sub_ann_" + tier}, whsec); c != 200 {
			t.Fatalf("webhook %s: %d", tier, c)
		}
		p, ok := s.store.Get(acct)
		if !ok || p.Tier != tier || p.Interval != "year" || !p.Active(time.Now()) {
			t.Fatalf("plan after annual webhook: %+v", p)
		}
		if s.PlanFor(acct) != tier {
			t.Fatalf("PlanFor %s", tier)
		}
	}
}

func TestQuotaBoundaries(t *testing.T) {
	us, _ := OpenUsageStore("")
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	pe := now.Add(30 * 24 * time.Hour)
	q := Quota{TrafficBytes: 1000, StorageBytes: 500, HostSwitches: 2}

	if err := us.CheckWrite("a", q, 500, now, pe); err != nil {
		t.Fatal(err)
	}
	_ = us.SetStorage("a", 500, now, pe)
	if err := us.CheckWrite("a", q, 1, now, pe); err == nil {
		t.Fatal("expected storage refuse")
	} else if eq, ok := err.(*ErrQuota); !ok || eq.Code != "storage_quota" || eq.HTTP != 402 {
		t.Fatalf("storage err: %v", err)
	}

	if err := us.CheckTraffic("a", q, now, pe); err != nil {
		t.Fatal(err)
	}
	_ = us.AddTraffic("a", q, 1000, now, pe)
	if err := us.CheckTraffic("a", q, now, pe); err == nil {
		t.Fatal("expected traffic refuse")
	} else if eq, ok := err.(*ErrQuota); !ok || eq.Code != "traffic_quota" || eq.HTTP != 429 {
		t.Fatalf("traffic err: %v", err)
	}

	if err := us.TryHostSwitch("a", q, true, now, pe); err != nil {
		t.Fatal(err)
	}
	if err := us.TryHostSwitch("a", q, true, now, pe); err != nil {
		t.Fatal("noop switch should be free")
	}
	if err := us.TryHostSwitch("a", q, false, now, pe); err != nil {
		t.Fatal(err)
	}
	if err := us.TryHostSwitch("a", q, true, now, pe); err == nil {
		t.Fatal("expected switch refuse")
	} else if eq, ok := err.(*ErrQuota); !ok || eq.Code != "host_switch_quota" || eq.HTTP != 402 {
		t.Fatalf("switch err: %v", err)
	}

	// Emerald unlimited switches
	eq := Quota{TrafficBytes: 1 << 40, StorageBytes: 500 << 30, HostSwitches: UnlimitedSwitches}
	for i := 0; i < 100; i++ {
		if err := us.ForceHostSwitch("em", eq, now, pe); err != nil {
			t.Fatal(err)
		}
	}

	// Monthly reset: jump a month, traffic clears, storage keeps
	_ = us.SetStorage("a", 400, now, pe)
	later := addMonths(now, 1).Add(time.Hour)
	u := us.Get("a", later, pe)
	if u.TrafficBytes != 0 || u.HostSwitches != 0 || u.StorageBytes != 400 {
		t.Fatalf("after rollover: %+v", u)
	}

	// Same quotas for every tier whether monthly or annual
	for _, tname := range []string{"basic", "bronze", "silver", "gold", "platinum", "emerald"} {
		qq, ok := QuotaFor(tname)
		if !ok || qq.TrafficBytes <= 0 || qq.StorageBytes <= 0 {
			t.Fatalf("quota %s: %+v", tname, qq)
		}
	}
	if q, _ := QuotaFor("emerald"); q.HostSwitches != UnlimitedSwitches {
		t.Fatal("emerald should be unlimited switches")
	}
	if q, _ := QuotaFor("basic"); q.TrafficBytes != 10<<30 || q.StorageBytes != 1<<30 || q.HostSwitches != 2 {
		t.Fatalf("basic quota: %+v", q)
	}
}

func TestHostingRouteSwitchBudget(t *testing.T) {
	_, f, h := testService(t)
	c, out := call(t, h, "POST", "/v1/billing/checkout", "host1", map[string]string{"plan": "basic", "idempotencyKey": "hostsw001"})
	if c != 200 {
		t.Fatalf("checkout: %d", c)
	}
	end := time.Now().Add(30 * 24 * time.Hour)
	f.pay(out["session"].(string), "sub_host", "basic", end)
	hook(t, h, "evt_host", "customer.subscription.created", map[string]string{"id": "sub_host"}, whsec)

	if c, _ := call(t, h, "POST", "/v1/billing/hosting", "host1", map[string]string{"action": "on"}); c != 200 {
		t.Fatalf("on: %d", c)
	}
	if c, _ := call(t, h, "POST", "/v1/billing/hosting", "host1", map[string]string{"action": "off"}); c != 200 {
		t.Fatalf("off: %d", c)
	}
	if c, out := call(t, h, "POST", "/v1/billing/hosting", "host1", map[string]string{"action": "on"}); c != 402 || out["error"] != "host_switch_quota" {
		t.Fatalf("third switch: %d %v", c, out)
	}
	c, me := call(t, h, "GET", "/v1/billing/me", "host1", nil)
	if c != 200 || me["interval"] != "month" {
		t.Fatalf("me: %d %v", c, me)
	}
	usage := me["usage"].(map[string]interface{})
	if usage["hostSwitches"].(float64) != 2 {
		t.Fatalf("usage switches: %v", usage)
	}
}
