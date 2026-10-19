package host

import (
	"embed"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Presets are plain TOML data files embedded in the binary (host/presets/*.toml). A preset is a
// bundle of pre-tuned settings plus a short plain-English reason for each one. Applying one
// only sets configuration values that the user can still edit; precedence is
// defaults < preset < config file < environment < flags.
//
//go:embed presets/*.toml
var presetFS embed.FS

// PresetFile is a recommended file for the preset's use case.
type PresetFile struct {
	Name       string `toml:"name" json:"name"`
	Box        string `toml:"box" json:"box,omitempty"`
	TTLSeconds int    `toml:"ttl_seconds" json:"ttl_seconds,omitempty"`
	Note       string `toml:"note" json:"note"`
}

// Preset is one settings profile.
type Preset struct {
	Name     string            `toml:"name" json:"name"`
	Title    string            `toml:"title" json:"title"`
	Order    int               `toml:"order" json:"order"`
	Summary  string            `toml:"summary" json:"summary"`
	Audience string            `toml:"audience" json:"audience"`
	Needs    []string          `toml:"needs" json:"needs,omitempty"`
	Guidance []string          `toml:"guidance" json:"guidance"`
	Warnings []string          `toml:"warnings" json:"warnings"`
	Why      map[string]string `toml:"why" json:"why"`
	Files    []PresetFile      `toml:"files" json:"files"`

	// Settings holds the values in file order-independent form (key -> value) for display.
	Settings map[string]interface{} `toml:"-" json:"settings"`
	raw      toml.Primitive
	md       toml.MetaData
}

var presets map[string]*Preset

func init() {
	presets = map[string]*Preset{}
	ents, err := presetFS.ReadDir("presets")
	if err != nil {
		panic(err)
	}
	for _, e := range ents {
		b, err := presetFS.ReadFile("presets/" + e.Name())
		if err != nil {
			panic(err)
		}
		p, err := ParsePreset(string(b))
		if err != nil {
			panic(fmt.Sprintf("preset %s: %v", e.Name(), err))
		}
		presets[p.Name] = p
	}
}

// ParsePreset parses preset TOML text (also used by tests).
func ParsePreset(src string) (*Preset, error) {
	var wrap struct {
		Preset
		Settings toml.Primitive `toml:"settings"`
	}
	md, err := toml.Decode(src, &wrap)
	if err != nil {
		return nil, err
	}
	p := wrap.Preset
	p.raw, p.md = wrap.Settings, md
	if p.Name == "" || p.Title == "" || p.Summary == "" {
		return nil, fmt.Errorf("name, title and summary are required")
	}
	var m map[string]interface{}
	if err := md.PrimitiveDecode(wrap.Settings, &m); err != nil {
		return nil, err
	}
	p.Settings = m
	// Reject keys that Config does not know: PrimitiveDecode into a Config reports them.
	var c Config
	if err := md.PrimitiveDecode(wrap.Settings, &c); err != nil {
		return nil, err
	}
	for _, k := range md.Undecoded() {
		ks := k.String()
		if strings.HasPrefix(ks, "settings.") {
			return nil, fmt.Errorf("unknown setting %q", ks)
		}
	}
	if p.Why == nil {
		p.Why = map[string]string{}
	}
	return &p, nil
}

// PresetNames lists preset names in display order.
func PresetNames() []string {
	var out []string
	for _, p := range AllPresets() {
		out = append(out, p.Name)
	}
	return out
}

// AllPresets returns every preset sorted by Order then name.
func AllPresets() []*Preset {
	out := make([]*Preset, 0, len(presets))
	for _, p := range presets {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// GetPreset finds a preset by name (case-insensitive).
func GetPreset(name string) (*Preset, error) {
	if p, ok := presets[strings.ToLower(strings.TrimSpace(name))]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("unknown preset %q (available: %s)", name, strings.Join(PresetNames(), ", "))
}

// ApplyTo sets the preset's values on cfg (only the keys the preset names).
func (p *Preset) ApplyTo(cfg *Config) error {
	return p.md.PrimitiveDecode(p.raw, cfg)
}

// SettingKeys returns the preset's setting keys, sorted.
func (p *Preset) SettingKeys() []string {
	ks := make([]string, 0, len(p.Settings))
	for k := range p.Settings {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// ConfigValues returns the effective value of every settable key of cfg as TOML-keyed values.
func ConfigValues(cfg Config) map[string]interface{} {
	out := map[string]interface{}{}
	t := reflect.TypeOf(cfg)
	v := reflect.ValueOf(cfg)
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("toml")
		if tag == "" || tag == "-" {
			continue
		}
		out[tag] = v.Field(i).Interface()
	}
	return out
}

// SettingChange is one row of a "what changed" diff.
type SettingChange struct {
	Key     string      `json:"key"`
	From    interface{} `json:"from"`
	To      interface{} `json:"to"`
	Why     string      `json:"why,omitempty"`
	Changed bool        `json:"changed"`
}

// Diff compares the preset's values with cfg (typically the effective config).
func (p *Preset) Diff(cfg Config) []SettingChange {
	cur := ConfigValues(cfg)
	var out []SettingChange
	for _, k := range p.SettingKeys() {
		next := cur[k]
		pv := p.Settings[k]
		out = append(out, SettingChange{Key: k, From: normalize(cur[k]), To: normalize(pv), Why: p.Why[k], Changed: !reflect.DeepEqual(normalize(next), normalize(pv))})
	}
	return out
}

func normalize(v interface{}) interface{} {
	switch t := v.(type) {
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case uint32:
		return float64(t)
	case float32:
		return float64(t)
	case []string:
		if t == nil {
			return []interface{}{}
		}
		o := make([]interface{}, len(t))
		for i, s := range t {
			o[i] = s
		}
		return o
	}
	return v
}
