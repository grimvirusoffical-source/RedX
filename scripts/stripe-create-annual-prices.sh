#!/usr/bin/env bash
# Create the six RedX Hosted *annual* Stripe Prices in TEST mode.
# Lookup keys: redx_hosted_<tier>_annual (amounts = 10× monthly / 2 months free).
#
# Usage:
#   STRIPE_SECRET_KEY=sk_test_... ./scripts/stripe-create-annual-prices.sh
#
# Refuses live keys. Does not print secrets. Idempotent: skips a lookup key that already exists.
#
# Live mode: Josh must create the same six prices in the Dashboard (or re-run with a live key
# after setting REDX_STRIPE_LIVE=1 and confirming). This script will not do that for you.
#
# Manual Stripe CLI equivalent (per tier), after finding the monthly product id:
#   stripe prices create \
#     --product prod_XXX \
#     --currency usd \
#     --unit-amount 20000 \
#     --recurring[interval]=year \
#     --lookup-key redx_hosted_basic_annual \
#     -d "metadata[app]=redx" -d "metadata[plan]=basic" -d "metadata[interval]=year"
set -euo pipefail

KEY="${STRIPE_SECRET_KEY:-}"
if [[ -z "$KEY" ]]; then
  echo "STRIPE_SECRET_KEY is not set" >&2
  exit 1
fi
case "$KEY" in
  sk_live_*|rk_live_*)
    echo "Refusing live Stripe key. Annual live prices need Josh; use a sk_test_ key." >&2
    exit 2
    ;;
  sk_test_*|rk_test_*) ;;
  *)
    echo "STRIPE_SECRET_KEY does not look like a test secret key" >&2
    exit 1
    ;;
esac

API="https://api.stripe.com/v1"
VER="2026-09-30.endive"
auth=(-u "${KEY}:")
# Never echo the key.
unset KEY

tiers=(basic:20000 bronze:45000 silver:60000 gold:80000 platinum:90000 emerald:100000)

echo "Creating annual RedX Hosted prices in TEST mode (10× monthly)…"
for pair in "${tiers[@]}"; do
  tier="${pair%%:*}"
  amount="${pair##*:}"
  monthly_lk="redx_hosted_${tier}_monthly"
  annual_lk="redx_hosted_${tier}_annual"

  # Already have annual?
  existing=$(curl -sS "${auth[@]}" -H "Stripe-Version: $VER" \
    -G "$API/prices" --data-urlencode "lookup_keys[0]=$annual_lk" --data-urlencode "active=true")
  if echo "$existing" | grep -q "\"lookup_key\": \"$annual_lk\""; then
    echo "  $annual_lk already exists — skip"
    continue
  fi

  # Find monthly price → product
  monthly=$(curl -sS "${auth[@]}" -H "Stripe-Version: $VER" \
    -G "$API/prices" --data-urlencode "lookup_keys[0]=$monthly_lk" --data-urlencode "active=true")
  product=$(echo "$monthly" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["data"][0]["product"] if d.get("data") else "")')
  if [[ -z "$product" ]]; then
    echo "  missing monthly price $monthly_lk — create monthly first" >&2
    exit 3
  fi

  curl -sS "${auth[@]}" -H "Stripe-Version: $VER" \
    -X POST "$API/prices" \
    -d "product=$product" \
    -d "currency=usd" \
    -d "unit_amount=$amount" \
    -d "recurring[interval]=year" \
    -d "lookup_key=$annual_lk" \
    -d "metadata[app]=redx" \
    -d "metadata[plan]=$tier" \
    -d "metadata[interval]=year" \
    -d "transfer_lookup_key=true" \
    >/dev/null
  echo "  created $annual_lk (\$$((amount/100))/year) on product $product"
done
echo "Done. Update the Stripe portal config so customers can switch monthly↔annual if needed."
