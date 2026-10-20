#!/usr/bin/env bash
# Crypto boundary check (JF rule: Red-SecretsXAI only). Fails if a non-test Go file imports
# crypto/* or golang.org/x/crypto outside the documented TLS / OIDC boundary below.
# Then prints, per binary, the crypto/* packages that arrive through go list -deps, so the
# transitive users (net/http -> crypto/tls) are visible.
set -u
cd "$(dirname "$0")/.."
# file|allowed imports (space separated). Everything else must use redx/internal/rsx.
ALLOW='
internal/tlspin/tlspin.go|crypto/tls crypto/x509
sdk/go/internal/tlspin/tlspin.go|crypto/tls crypto/x509
host/tlsutil.go|crypto/tls crypto/x509 crypto/x509/pkix crypto/ecdsa crypto/elliptic
host/client/client.go|crypto/tls crypto/x509
host/cluster.go|crypto/tls crypto/x509
host/daemon.go|crypto/tls
host/redxdb_link.go|crypto/tls
cmd/redx/doctor.go|crypto/tls crypto/x509
cmd/redx/subscribe.go|crypto/tls
sdk/go/redx/client.go|crypto/tls crypto/x509
host/accounts_oidc.go|crypto/ecdsa crypto/elliptic crypto/ecdh
host/accountsfake/fake.go|crypto/ecdsa crypto/elliptic crypto/rand crypto/sha256
'
bad=0
while IFS= read -r f; do
  imps=$(go list -f '{{join .Imports " "}}' "./$(dirname "$f")" >/dev/null 2>&1; awk '/^import \(/{f=1;next} f&&/^\)/{f=0} f{print} /^import "/{print $2}' "$f" | grep -oE '"(crypto/[a-z0-9/]+|golang.org/x/crypto[a-z0-9/]*)"' | tr -d '"')
  [ -z "$imps" ] && continue
  allowed=$(printf '%s\n' "$ALLOW" | awk -F'|' -v f="$f" '$1==f{print $2}')
  for i in $imps; do
    case " $allowed " in *" $i "*) ;; *) echo "VIOLATION $f imports $i"; bad=$((bad+1));; esac
  done
done < <(git ls-files '*.go' | grep -v '_test.go$' | grep -v '^internal/rsx/' | grep -v '^sdk/go/internal/rsx/')
echo "boundary violations: $bad"
for p in ./cmd/redxd ./cmd/redx ./cmd/redx-launcher; do
  echo "== go list -deps $p (crypto/* and x/crypto)"
  CGO_ENABLED=0 go list -deps "$p" | grep -E '^(crypto/|golang.org/x/crypto)' | tr '\n' ' '; echo
done
echo "== direct importers of crypto/* among redx packages"
CGO_ENABLED=0 go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./... | awk '{o=$1; s=""; for(i=2;i<=NF;i++) if($i ~ /^crypto\// || $i ~ /^golang.org\/x\/crypto/) s=s" "$i; if(s!="") print o s}'
[ $bad -eq 0 ]
