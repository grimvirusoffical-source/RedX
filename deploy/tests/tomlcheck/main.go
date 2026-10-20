// Command tomlcheck loads a redx.toml through the real host config loader (host.Config.ApplyFile, the same
// code redxd uses) and prints the install-written fields as JSON, so shell tests can compare exact values.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"redx/host"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: tomlcheck <redx.toml>")
		os.Exit(2)
	}
	c := host.DefaultConfig()
	if err := c.ApplyFile(os.Args[1], true); err != nil {
		fmt.Fprintln(os.Stderr, "parse error:", err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"data_dir": c.DataDir, "listen": c.Listen, "tls": c.TLS, "tls_cert": c.TLSCert, "tls_key": c.TLSKey,
		"role": c.Role, "peers": c.Peers,
	})
}
