// Command fake-accounts serves the in-memory Red-XAI Accounts fake for the headless console test and local
// development. It prints "ISSUER <url>" once it listens. Never use it in production.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"redx/host/accountsfake"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "listen address (loopback only)")
	flag.Parse()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	f := accountsfake.New()
	f.Issuer = "http://" + ln.Addr().String()
	fmt.Println("ISSUER " + f.Issuer)
	_ = os.Stdout.Sync()
	log.Fatal(http.Serve(ln, f.Handler()))
}
