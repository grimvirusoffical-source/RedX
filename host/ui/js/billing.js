// RedX Hosted checkout: /ui/billing.html?plan=gold&interval=year (and ?return=1&session_id=… after paying).
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

// Tier descriptions. Prices always come from Stripe (/v1/billing/plans), never from here.
var BADGE = { basic: "Starter", silver: "Popular", emerald: "Top tier" };
function features(interval) {
  var bill = interval === "year" ? "Annual billing (10× monthly = 2 months free), cancel any time" : "Monthly billing, cancel any time";
  return ["Hosted RedX databases on Red-XAI servers", "Tied to your Red-XAI Account", bill,
    "Same quotas either way (traffic, storage, host switches)", "Switch tiers in Manage billing (prorated)"];
}

function fmtQuota(q) {
  if (!q) return [];
  function gb(n) {
    if (n >= (1 << 40)) return (n / (1 << 40)) + " TB";
    return (n / (1 << 30)) + " GB";
  }
  var sw = q.hostSwitches < 0 ? "unlimited host on/off switches / month" : (q.hostSwitches + " host on/off switches / month");
  return [gb(q.trafficBytes) + " traffic / month", gb(q.storageBytes) + " storage", sw];
}

function items(list) {
  return (list || []).filter(function (p) { return p.available !== false; }).map(function (p) {
    var period = p.interval || "month";
    var itemKey = p.key + "_" + (period === "year" ? "year" : "month");
    return {
      key: itemKey, plan: p.key, interval: period === "year" ? "year" : "month",
      name: "RedX Hosted " + p.name + (period === "year" ? " (annual)" : ""),
      amountCents: p.amount, currency: p.currency || "usd", period: period,
      badge: BADGE[p.key], blurb: "The " + p.name + " tier of RedX Hosted.",
      features: features(period).concat(fmtQuota(p.quota)),
    };
  });
}

export var REDX_THEME = {
  name: "RedX", logoSrc: "/ui/icons/redx-128.png", homeHref: "/ui/", homeLabel: "Back to the console",
  thanks: "Your RedX Hosted plan is on", pickTitle: "Choose a RedX Hosted plan",
  legal: "Billed by Red-XAI LLC (monthly or annual). Change or cancel any time in Manage billing.",
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
var DEMO = [];
[["basic", "Basic", 2000, 20000], ["bronze", "Bronze", 4500, 45000], ["silver", "Silver", 6000, 60000],
 ["gold", "Gold", 8000, 80000], ["platinum", "Platinum", 9000, 90000], ["emerald", "Emerald", 10000, 100000]]
  .forEach(function (d) {
    DEMO.push({ key: d[0], name: d[1], amount: d[2], currency: "usd", interval: "month", available: true,
      quota: { trafficBytes: 10<<30, storageBytes: 1<<30, hostSwitches: 2 } });
    DEMO.push({ key: d[0], name: d[1], amount: d[3], currency: "usd", interval: "year", available: true,
      quota: { trafficBytes: 10<<30, storageBytes: 1<<30, hostSwitches: 2 } });
  });

function pickKey() {
  var plan = q.get("plan") || "";
  var iv = q.get("interval") || "month";
  if (iv === "annual" || iv === "yearly") iv = "year";
  if (plan.indexOf("_") >= 0) return plan; // already composite
  if (!plan) return "";
  return plan + "_" + (iv === "year" ? "year" : "month");
}

var backend = preview ? {
  load: async function () { return { publishableKey: "", items: items(DEMO) }; },
} : {
  load: async function () {
    var d = await call("GET", "/v1/billing/plans");
    if (!d.enabled) throw new Error("RedX Hosted billing is not switched on for this server yet.");
    return { publishableKey: d.publishableKey, items: items(d.plans) };
  },
  start: function (item, key) {
    return call("POST", "/v1/billing/checkout", { plan: item.plan || item.key.split("_")[0], interval: item.interval || item.period || "month", idempotencyKey: key });
  },
  status: function (s) { return call("GET", "/v1/billing/checkout/" + encodeURIComponent(s)); },
};

mountCheckout({ root: document.getElementById("root"), theme: REDX_THEME, backend: backend, preview: preview,
  item: pickKey(), returnPage: q.get("return") === "1", session: q.get("session_id") || "" });
