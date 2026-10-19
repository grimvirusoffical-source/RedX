// RedX Hosted checkout: /ui/billing.html?plan=gold (and ?return=1&session_id=… after paying).
// redxd makes the Stripe Checkout Session for the signed-in Red-XAI Account; this page only renders
// Stripe's Payment Element in the console's crimson theme. No card data touches redxd.
import { mountCheckout } from './checkout-engine.js';

var K = "redx.key";
var KEY = "";
try { KEY = sessionStorage.getItem(K) || localStorage.getItem(K) || ""; } catch (e) { /* storage blocked */ }

async function call(method, path, body) {
  var o = { method: method, headers: { Authorization: "Bearer " + KEY } };
  if (body) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(body); }
  var r = await fetch(path, o);
  var d = await r.json().catch(function () { return {}; });
  if (r.status === 401 || d.error === "account_required") throw new Error("Sign in to the RedX console with your Red-XAI Account first.");
  if (d.error === "manage_in_portal") throw new Error(d.message + ".");
  if (!r.ok) throw new Error(d.message || d.error || ("HTTP " + r.status));
  return d;
}

// Tier descriptions. Prices always come from Stripe (/v1/billing/plans), never from here. The per-tier
// limits are not written down yet, so the page promises nothing beyond the plan itself (docs/billing.md).
var BADGE = { basic: "Starter", silver: "Popular", emerald: "Top tier" };
var COMMON = ["Hosted RedX databases on Red-XAI servers", "Tied to your Red-XAI Account", "Monthly billing, cancel any time", "Switch tiers in Manage billing (prorated)"];

function items(list) {
  return (list || []).filter(function (p) { return p.available !== false; }).map(function (p) {
    return { key: p.key, name: "RedX Hosted " + p.name, amountCents: p.amount, currency: p.currency || "usd", period: p.interval || "month",
      badge: BADGE[p.key], blurb: "The " + p.name + " tier of RedX Hosted.", features: COMMON };
  });
}

export var REDX_THEME = {
  name: "RedX", logoSrc: "/ui/icons/redx-128.png", homeHref: "/ui/", homeLabel: "Back to the console",
  thanks: "Your RedX Hosted plan is on", pickTitle: "Choose a RedX Hosted plan",
  legal: "Billed monthly by Red-XAI LLC. Change or cancel any time in Manage billing.",
  appearance: {
    theme: "night", labels: "floating",
    variables: { colorPrimary: "#f2495a", colorBackground: "#150d0f", colorText: "#f5ecec", colorTextSecondary: "#b0a0a3", colorDanger: "#ff5d6c",
      colorSuccess: "#3ecf8e", fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif', borderRadius: "12px", spacingUnit: "4px", fontSizeBase: "15px" },
    rules: {
      ".Input": { border: "1px solid #33232a", boxShadow: "none" },
      ".Input:focus": { border: "1px solid #f2495a", boxShadow: "0 0 0 1px #f2495a, 0 0 16px rgba(242,73,90,.40)" },
      ".Tab": { border: "1px solid #33232a", backgroundColor: "#150d0f" },
      ".Tab--selected": { border: "1px solid #f2495a", boxShadow: "0 0 0 1px #f2495a" },
      ".Label": { color: "#b0a0a3" },
    },
  },
};

var q = new URLSearchParams(location.search);
var preview = q.get("preview") === "1";
var DEMO = [["basic", "Basic", 2000], ["bronze", "Bronze", 4500], ["silver", "Silver", 6000], ["gold", "Gold", 8000], ["platinum", "Platinum", 9000], ["emerald", "Emerald", 10000]]
  .map(function (d) { return { key: d[0], name: d[1], amount: d[2], currency: "usd", interval: "month" }; });
var backend = preview ? {
  load: async function () { return { publishableKey: "", items: items(DEMO) }; },
} : {
  load: async function () {
    var d = await call("GET", "/v1/billing/plans");
    if (!d.enabled) throw new Error("RedX Hosted billing is not switched on for this server yet.");
    return { publishableKey: d.publishableKey, items: items(d.plans) };
  },
  start: function (item, key) { return call("POST", "/v1/billing/checkout", { plan: item.key, idempotencyKey: key }); },
  status: function (s) { return call("GET", "/v1/billing/checkout/" + encodeURIComponent(s)); },
};

mountCheckout({ root: document.getElementById("root"), theme: REDX_THEME, backend: backend, preview: preview,
  item: q.get("plan") || "", returnPage: q.get("return") === "1", session: q.get("session_id") || "" });
