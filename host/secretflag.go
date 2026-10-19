package host

import "flag"

// SecretString is a flag.Value for secrets (API keys, join links/codes, TLS pins taken from the environment).
// Its String() is always empty, so `-h` never prints the current value as a default; the usage text says where the
// value comes from instead. `redx <cmd> -h` used to print the full REDX_KEY.
type SecretString struct{ P *string }

func (s SecretString) String() string { return "" }

// Set stores the value given on the command line.
func (s SecretString) Set(v string) error { *s.P = v; return nil }

// SecretVar registers a secret string flag whose initial value (for example from an environment variable) is kept in
// *p but never shown by -h. source describes it for the help text, e.g. "$REDX_KEY".
func SecretVar(fs *flag.FlagSet, p *string, name, usage, source string) {
	if *p != "" && source != "" {
		usage += " (currently set from " + source + ")"
	} else if source != "" {
		usage += " (default: " + source + ")"
	}
	fs.Var(SecretString{p}, name, usage)
}
