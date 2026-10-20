# e2e-oidc-idp

External Accounts-contract OIDC IdP (ES256) used by `test_accounts_oidc.py`.
Built from the host-integration tree (`cmd/e2e-oidc-idp` + `host/accountsfake`).

```sh
cd /workspace/redx-integration
go build -o /workspace/redx-e2e-bin/e2e-oidc-idp ./cmd/e2e-oidc-idp
```

`Identity.force_iss` / `force_aud` (accountsfake) override ID-token claims for
audience/issuer confusion probes. Redirect allow-list: `POST /test/redirects`.
