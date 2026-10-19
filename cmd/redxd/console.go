package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"redx/host"
)

// autoOpen is set only by a foreground `redxd run`; services and tests never open a browser.
var autoOpen bool

// stripOpenFlags removes --open / --no-open (handled here, unknown to the config flag set).
func stripOpenFlags(args []string) ([]string, string) {
	mode := ""
	var out []string
	for _, a := range args {
		switch a {
		case "--open", "-open":
			mode = "always"
		case "--no-open", "-no-open":
			mode = "never"
		default:
			out = append(out, a)
		}
	}
	return out, mode
}

// consoleURL is where a browser on THIS machine reaches the console.
func consoleURL(cfg host.Config) string {
	scheme := "http"
	if cfg.TLS != "off" && cfg.TLS != "" {
		scheme = "https"
	}
	hostPart, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return scheme + "://127.0.0.1:7777/"
	}
	switch hostPart {
	case "", "0.0.0.0", "::", "[::]":
		hostPart = "127.0.0.1"
	}
	if strings.Contains(hostPart, ":") {
		hostPart = "[" + hostPart + "]"
	}
	return scheme + "://" + hostPart + ":" + port + "/"
}

func headless() bool {
	if os.Getenv("CI") != "" || os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return true
	}
	if runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return true
	}
	return false
}

// shouldOpen decides about the best-effort browser launch: only for a foreground run, never when
// REDX_NO_OPEN is set or the machine is headless, and automatically only the first time (while
// setup is pending, or until a marker file says the console has been opened once). --open forces it.
func shouldOpen(cfg host.Config, flagMode string, setupPending bool) bool {
	if flagMode == "never" || os.Getenv("REDX_NO_OPEN") != "" || !autoOpen {
		return false
	}
	if flagMode == "always" {
		return true
	}
	if headless() {
		return false
	}
	marker := filepath.Join(cfg.DataDir, "console.opened")
	if _, err := os.Stat(marker); err == nil && !setupPending {
		return false
	}
	_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
	return true
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// runOpen implements `redxd open`: open the console of the host configured on this machine.
func runOpen(args []string) error {
	cfg, err := host.LoadConfig(args, os.Getenv, flag.NewFlagSet("open", flag.ContinueOnError))
	if err != nil {
		return err
	}
	url := consoleURL(cfg)
	fmt.Println("opening", url)
	if err := openBrowser(url); err != nil {
		return fmt.Errorf("could not start a browser (%v); open %s yourself", err, url)
	}
	return nil
}

// runJoin implements `redxd join <link | URL CODE>`.
func runJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	dataDir := fs.String("data-dir", envOrDefault("REDX_DATA_DIR", host.DefaultDataDir()), "data directory of this node")
	advertise := fs.String("advertise", os.Getenv("REDX_ADVERTISE"), "URL other nodes use to reach THIS node, e.g. http://192.168.1.20:7777")
	noRun := fs.Bool("no-run", false, "join only; start redxd yourself (or the service) afterwards")
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) == 0 {
		return errors.New("usage: redxd join <join link>   or   redxd join <leader-url> <code>   (get them from the leader's Add a device page)")
	}
	sp, err := host.ParseJoin(strings.Join(pos, " "))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id, err := host.RedeemJoin(ctx, *dataDir, sp, *advertise)
	if err != nil {
		return fmt.Errorf("%w%s", err, host.JoinErrorHint(err))
	}
	fmt.Printf("joined %s as node %q (data dir %s).\n", sp.Leader, id, *dataDir)
	if *noRun {
		fmt.Println("Start this node with:  redxd run --data-dir", *dataDir)
		return nil
	}
	fmt.Println("starting as a follower; press Ctrl+C to stop.")
	return runForeground([]string{"--data-dir", *dataDir, "--role", "follower"})
}

func envOrDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
