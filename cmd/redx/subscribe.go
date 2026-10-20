package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"

	"github.com/gorilla/websocket"

	"redx/host/client"
)

// dialSubscribe opens the subscription socket, honouring --pin and --insecure like every other command.
func dialSubscribe(g globals, path string) (*websocket.Conn, *http.Response, error) {
	u, err := url.Parse(g.addr)
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	if g.db != "" {
		u.Path = "/v1/db/" + g.db + "/subscribe"
	} else {
		u.Path = "/v1/subscribe"
	}
	u.RawQuery = url.Values{"path": {path}}.Encode()
	d := *websocket.DefaultDialer
	switch {
	case g.pin != "":
		d.TLSClientConfig = client.PinnedTLSConfig(g.pin)
	case g.insecure:
		d.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return d.Dial(u.String(), http.Header{"Authorization": {"Bearer " + g.key}})
}

func subscribe(g globals, path string) {
	conn, resp, err := dialSubscribe(g, path)
	if err != nil {
		if resp != nil {
			die("subscribe refused: %s", resp.Status)
		}
		die("%v", err)
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() { <-ctx.Done(); conn.Close() }()
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "connection closed:", strings.TrimSpace(err.Error()))
			}
			return
		}
		fmt.Println(string(msg))
	}
}
