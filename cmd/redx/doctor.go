package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"redx/host"
	"redx/host/client"
)

type check struct{ name, status, detail string }

func cmdDoctor(args []string) {
	var g globals
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	g.bind(fs)
	cfgFile := fs.String("config", os.Getenv("REDX_CONFIG"), "redxd config file to validate")
	tlsMode := fs.String("tls", "", "the redxd --tls value, if you pass it as a flag (off|auto|files)")
	tlsCert := fs.String("tls-cert", "", "the redxd --tls-cert file, if you pass it as a flag")
	tlsKey := fs.String("tls-key", "", "the redxd --tls-key file, if you pass it as a flag (checked against the certificate)")
	parse(fs, args)
	var res []check
	add := func(name, status, detail string) { res = append(res, check{name, status, detail}) }

	// Which data directory? If --data-dir / REDX_DATA_DIR was not given and a daemon is answering, ask
	// the daemon (needs --key) so we check the directory it really uses, not this machine's default.
	explicitDD := os.Getenv("REDX_DATA_DIR") != ""
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "data-dir" {
			explicitDD = true
		}
	})
	daemonUp, ddFromDaemon, daemonStatus := false, false, false
	var dstatus struct {
		DataDir string        `json:"data_dir"`
		TLS     string        `json:"tls"`
		Cert    host.CertInfo `json:"tls_cert"`
		Warning string        `json:"tls_warning"`
	}
	{
		pc, pcancel := context.WithTimeout(context.Background(), 3*time.Second)
		if st, _, _, err := client.New(g.addr, "", g.pin, g.insecure).Raw(pc, "GET", "/healthz", nil, nil); err == nil && st == http.StatusOK {
			daemonUp = true
			if g.key != "" {
				if err := client.New(g.addr, g.key, g.pin, g.insecure).JSON(pc, "GET", "/v1/admin/status", nil, &dstatus); err == nil {
					daemonStatus = true
					if dstatus.DataDir != "" && !explicitDD {
						g.dataDir, ddFromDaemon = dstatus.DataDir, true
					}
				}
			}
		}
		pcancel()
	}

	add("platform", "ok", fmt.Sprintf("%s/%s go %s redx %s", runtime.GOOS, runtime.GOARCH, runtime.Version(), host.Version))

	// config
	cfg := host.DefaultConfig()
	cfg.DataDir = g.dataDir
	if *cfgFile != "" {
		if err := cfg.ApplyFile(*cfgFile, true); err != nil {
			add("config", "FAIL", err.Error())
		} else {
			add("config", "ok", *cfgFile)
		}
	} else if df := filepath.Join(cfg.DataDir, "redx.toml"); true {
		if err := cfg.ApplyFile(df, false); err != nil {
			add("config", "FAIL", err.Error())
		} else if _, serr := os.Stat(df); serr == nil {
			add("config", "ok", "loaded "+df)
		} else {
			add("config", "ok", "defaults (no redx.toml in the data dir "+cfg.DataDir+")")
		}
	}
	_ = cfg.ApplyEnv(os.Getenv)
	if *tlsMode != "" {
		cfg.TLS = *tlsMode
	}
	if *tlsCert != "" {
		cfg.TLSCert = *tlsCert
		if *tlsMode == "" && cfg.TLS == "off" {
			cfg.TLS = "files"
		}
	}
	if *tlsKey != "" {
		cfg.TLSKey = *tlsKey
	}
	// Only the certificate was handed to doctor: check it, and do not fail the config for the missing key.
	certOnly := cfg.TLS == "files" && cfg.TLSCert != "" && cfg.TLSKey == "" && *tlsCert != ""
	vcfg := cfg
	if certOnly {
		vcfg.TLSKey = cfg.TLSCert
	}
	if err := vcfg.Validate(); err != nil {
		add("config valid", "FAIL", err.Error())
	}
	if certOnly {
		add("tls key", "info", "not checked: pass --tls-key FILE to check that the key matches the certificate")
	} else if cfg.TLS == "files" && cfg.TLSCert != "" && cfg.TLSKey != "" {
		if _, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey); err != nil {
			add("tls key", "FAIL", "certificate and key do not load as a pair: "+err.Error())
		} else {
			add("tls key", "ok", "matches the certificate")
		}
	}

	// data dir
	if st, err := os.Stat(cfg.DataDir); err != nil && daemonUp && !ddFromDaemon && !explicitDD {
		add("data dir", "info", fmt.Sprintf("a daemon is running at %s but its data directory is unknown (%s is only this machine's default); pass --key to ask the daemon, or --data-dir", g.addr, cfg.DataDir))
	} else if err != nil {
		add("data dir", "warn", fmt.Sprintf("%s does not exist yet (redxd creates it on first start)", cfg.DataDir))
	} else if !st.IsDir() {
		add("data dir", "FAIL", cfg.DataDir+" is not a directory")
	} else {
		tf := filepath.Join(cfg.DataDir, ".doctor-write-test")
		if err := os.WriteFile(tf, []byte("x"), 0o600); err != nil {
			add("data dir", "FAIL", "not writable: "+err.Error())
		} else {
			os.Remove(tf)
			src := " (writable)"
			if ddFromDaemon {
				src = " (the running daemon's directory, writable)"
			}
			add("data dir", "ok", cfg.DataDir+src)
		}
		if free, err := freeBytes(cfg.DataDir); err == nil {
			s := "ok"
			if free < 512<<20 {
				s = "warn"
			}
			add("free disk", s, fmt.Sprintf("%.1f GiB free", float64(free)/(1<<30)))
		}
		ksPath := filepath.Join(cfg.DataDir, "keys.red-xai-keys")
		if st, err := os.Stat(ksPath); err == nil {
			if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
				add("keystore perms", "FAIL", fmt.Sprintf("%s is %v; run chmod 600", ksPath, st.Mode().Perm()))
			}
			ks, err := host.OpenKeystore(ksPath, host.KeystoreOptions{Passphrase: os.Getenv("REDX_KEYSTORE_PASSPHRASE")})
			if err != nil {
				add("keystore", "FAIL", err.Error())
			} else {
				active, expired := 0, 0
				for _, r := range ks.List() {
					if r.Active(time.Now()) == nil {
						active++
					} else {
						expired++
					}
				}
				add("keystore", "ok", fmt.Sprintf("%d active key(s), %d revoked/expired", active, expired))
			}
		} else {
			add("keystore", "warn", "no keystore yet (created with the first admin key on first start)")
		}
	}

	// TLS certificate: checked whenever the config names one, even before the data dir exists,
	// and whatever way it was given (redx.toml, --config, env, or the redxd flags repeated here).
	cert := filepath.Join(cfg.DataDir, "tls", "cert.pem")
	if cfg.TLS == "files" && cfg.TLSCert != "" {
		cert = cfg.TLSCert
	}
	if fileExists(cert) {
		ci := host.CertStatus(cert, time.Now())
		switch ci.State {
		case "ok":
			add("tls cert", "ok", fmt.Sprintf("%s expires %s (%d days)", cert, ci.NotAfter.Format("2006-01-02"), ci.DaysLeft))
		case "expiring":
			add("tls cert", "warn", ci.Message)
		default:
			add("tls cert", "FAIL", ci.Message)
		}
	} else if cfg.TLS == "files" {
		add("tls cert", "FAIL", "tls=files but the certificate file "+cert+" does not exist")
	}
	// The running daemon knows the certificate it really serves (e.g. one passed as a redxd flag that
	// doctor cannot see): report its own judgement too.
	if daemonStatus && dstatus.TLS != "" && dstatus.TLS != "off" {
		switch dstatus.Cert.State {
		case "ok":
			add("served tls cert", "ok", fmt.Sprintf("the daemon's certificate expires %s (%d days)", dstatus.Cert.NotAfter.Format("2006-01-02"), dstatus.Cert.DaysLeft))
		case "expiring":
			add("served tls cert", "warn", "the daemon reports: "+dstatus.Warning)
		case "":
		default:
			add("served tls cert", "FAIL", "the daemon reports: "+dstatus.Warning)
		}
	}

	// port / daemon
	cl := client.New(g.addr, "", g.pin, g.insecure)
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, _, body, err := cl.Raw(c, "GET", "/healthz", nil, nil)
	switch {
	case err == nil && st == http.StatusOK:
		add("daemon", "ok", g.addr+" answered /healthz: "+trim(body))
		if g.key != "" {
			var cs host.ClusterStatus
			if err := client.New(g.addr, g.key, g.pin, g.insecure).JSON(c, "GET", "/v1/cluster/status", nil, &cs); err != nil {
				add("api key", "FAIL", err.Error())
			} else {
				add("api key", "ok", "admin key accepted")
				bad := 0
				for _, m := range cs.Members {
					if !m.Healthy {
						bad++
					}
				}
				s := "ok"
				if bad > 0 || cs.LastError != "" {
					s = "warn"
				}
				add("cluster", s, fmt.Sprintf("role=%s members=%d unhealthy=%d offset=%d %s", cs.Role, len(cs.Members), bad, cs.Offset, cs.LastError))
			}
		} else {
			add("api key", "warn", "no --key/REDX_KEY given; skipped authenticated checks")
		}
	default:
		// Not running: is the configured port free to bind?
		if ln, lerr := net.Listen("tcp", cfg.Listen); lerr != nil {
			add("daemon", "warn", fmt.Sprintf("%s unreachable (%v) and %s cannot be bound: %v", g.addr, err, cfg.Listen, lerr))
		} else {
			ln.Close()
			add("daemon", "warn", fmt.Sprintf("redxd is not running at %s; %s is free to bind", g.addr, cfg.Listen))
		}
	}
	if !host.IsLoopbackAddr(cfg.Listen) && cfg.TLS == "off" {
		add("exposure", "FAIL", fmt.Sprintf("listen=%s is not loopback and TLS is off: keys/data would travel in clear text", cfg.Listen))
	}

	bad := 0
	for _, r := range res {
		fmt.Printf("[%-4s] %-15s %s\n", r.status, r.name, r.detail)
		if r.status == "FAIL" {
			bad++
		}
	}
	if bad > 0 {
		fmt.Printf("\n%d problem(s) found.\n", bad)
		os.Exit(1)
	}
	fmt.Println("\nno blocking problems found.")
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func trim(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	return string(b)
}
