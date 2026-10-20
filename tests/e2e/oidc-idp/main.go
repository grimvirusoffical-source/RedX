// Standalone Red-XAI Accounts-contract OIDC IdP for local E2E.
// Speaks discovery + authorize + token + JWKS (ES256). Not linked into redxd.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"redx/host/accountsfake"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	flag.Parse()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	f := accountsfake.New()
	f.Issuer = "http://" + ln.Addr().String()
	f.SetNext(accountsfake.Identity{
		Sub: "rxa_E2E000000000000000000000001", Email: "user@example.com",
		EmailVerified: true, Username: "e2e_user", AMR: []string{"pwd"},
	})
	mux := http.NewServeMux()
	mux.Handle("/", f.Handler())
	mux.HandleFunc("/test/next", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var id accountsfake.Identity
		if json.NewDecoder(r.Body).Decode(&id) != nil {
			http.Error(w, "bad json", 400)
			return
		}
		f.SetNext(id)
		w.WriteHeader(204)
	})
	mux.HandleFunc("/test/redirects", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		var body struct {
			Redirects []string `json:"redirects"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "bad json", 400)
			return
		}
		// nil/empty = accept any (accountsfake: len==0 means any)
		f.Redirects = append([]string{}, body.Redirects...)
		w.WriteHeader(204)
	})
	fmt.Fprintf(os.Stdout, "ISSUER=%s\n", f.Issuer)
	log.Fatal(http.Serve(ln, mux))
}
