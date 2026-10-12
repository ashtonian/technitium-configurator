package technitium

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// AppConfig declares a DNS App to install and, optionally, its config.
type AppConfig struct {
	Name string `yaml:"name"`
	Url  string `yaml:"url"`
	// Config is passed to the app as JSON unchanged. When it is omitted the
	// app's current config is left alone.
	Config yaml.Node `yaml:"config,omitempty"`
}

// ConfigJSON returns the app config as JSON, or ok=false when none is set.
// Numbers keep their exact digits; apps read 64-bit integers that a float
// would round.
func (a *AppConfig) ConfigJSON() (config string, ok bool, err error) {
	if a.Config.Kind == 0 {
		return "", false, nil
	}
	n := &a.Config
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" {
		return "", false, nil
	}
	var buf bytes.Buffer
	w := &yamlWalk{expanding: map[*yaml.Node]bool{}, budget: maxYAMLValues}
	if err := w.toJSON(n, &buf); err != nil {
		return "", false, fmt.Errorf("config of app %q: %w", a.Name, err)
	}
	return buf.String(), true, nil
}

// maxYAMLValues bounds how many values a config may expand to through
// aliases, so a small file cannot expand without limit.
const maxYAMLValues = 1 << 20

// yamlWalk writes YAML nodes as JSON. Merge keys ("<<") are resolved as YAML
// defines them; duplicate keys, aliases that contain themselves and runaway
// alias expansion are errors. Integers are written in decimal from their
// text and floats keep their digits, so nothing passes through a float64.
type yamlWalk struct {
	expanding map[*yaml.Node]bool // alias targets being written
	budget    int
}

func (w *yamlWalk) toJSON(n *yaml.Node, buf *bytes.Buffer) error {
	if w.budget--; w.budget < 0 {
		return errors.New("the config expands to too many values through aliases")
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			buf.WriteString("null")
			return nil
		}
		return w.toJSON(n.Content[0], buf)
	case yaml.AliasNode:
		return w.expand(n, func(target *yaml.Node) error { return w.toJSON(target, buf) })
	case yaml.MappingNode:
		entries, err := w.mappingEntries(n)
		if err != nil {
			return err
		}
		buf.WriteByte('{')
		for i, e := range entries {
			if i > 0 {
				buf.WriteByte(',')
			}
			key, _ := json.Marshal(e.key.Value)
			buf.Write(key)
			buf.WriteByte(':')
			if err := w.toJSON(e.value, buf); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case yaml.SequenceNode:
		buf.WriteByte('[')
		for i, c := range n.Content {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := w.toJSON(c, buf); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case yaml.ScalarNode:
		return scalarToJSON(n, buf)
	default:
		return fmt.Errorf("line %d: unsupported YAML node", n.Line)
	}
	return nil
}

// expand calls fn with an alias's target, failing when the target is
// already being written, which means it contains itself.
func (w *yamlWalk) expand(alias *yaml.Node, fn func(*yaml.Node) error) error {
	target := alias.Alias
	if w.expanding[target] {
		return fmt.Errorf("line %d: alias *%s refers to a value that contains it", alias.Line, alias.Value)
	}
	w.expanding[target] = true
	defer delete(w.expanding, target)
	return fn(target)
}

type mappingEntry struct{ key, value *yaml.Node }

// mappingEntries lists a mapping's keys with merge keys resolved: the
// mapping's own keys come first and win, then keys merged from "<<" in
// order, where an earlier source wins over a later one. A key the mapping
// defines twice is an error.
func (w *yamlWalk) mappingEntries(n *yaml.Node) ([]mappingEntry, error) {
	var out []mappingEntry
	var merges []*yaml.Node
	own := map[string]int{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind == yaml.ScalarNode && k.ShortTag() == "!!merge" {
			merges = append(merges, v)
			continue
		}
		if k.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("line %d: a JSON object key must be a scalar", k.Line)
		}
		if line, dup := own[k.Value]; dup {
			return nil, fmt.Errorf("line %d: key %q is already defined at line %d", k.Line, k.Value, line)
		}
		own[k.Value] = k.Line
		out = append(out, mappingEntry{k, v})
	}
	seen := map[string]bool{}
	for key := range own {
		seen[key] = true
	}
	var merge func(src *yaml.Node) error
	merge = func(src *yaml.Node) error {
		switch src.Kind {
		case yaml.AliasNode:
			return w.expand(src, merge)
		case yaml.MappingNode:
			entries, err := w.mappingEntries(src)
			if err != nil {
				return err
			}
			for _, e := range entries {
				if !seen[e.key.Value] {
					seen[e.key.Value] = true
					out = append(out, e)
				}
			}
			return nil
		default:
			return fmt.Errorf("line %d: a merge key needs a mapping or a list of mappings", src.Line)
		}
	}
	for _, m := range merges {
		sources := []*yaml.Node{m}
		if resolved := resolveAlias(m); resolved.Kind == yaml.SequenceNode {
			sources = resolved.Content
		}
		for _, src := range sources {
			if err := merge(src); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func resolveAlias(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func scalarToJSON(n *yaml.Node, buf *bytes.Buffer) error {
	switch n.ShortTag() {
	case "!!null":
		buf.WriteString("null")
	case "!!bool":
		var b bool
		if err := n.Decode(&b); err != nil {
			return fmt.Errorf("line %d: %w", n.Line, err)
		}
		buf.WriteString(strconv.FormatBool(b))
	case "!!int":
		i, ok := new(big.Int).SetString(strings.ReplaceAll(n.Value, "_", ""), 0)
		if !ok {
			return fmt.Errorf("line %d: %q is not an integer", n.Line, n.Value)
		}
		buf.WriteString(i.String())
	case "!!float":
		num, ok := jsonNumber(n.Value)
		if !ok {
			return fmt.Errorf("line %d: %s cannot be represented in JSON", n.Line, n.Value)
		}
		buf.WriteString(num)
	default:
		s, _ := json.Marshal(n.Value)
		buf.Write(s)
	}
	return nil
}

// jsonNumber rewrites a YAML float as a JSON number without changing its
// digits: it drops a leading "+" and "_" separators and supplies the "0"
// JSON requires around a bare decimal point. .inf and .nan have no JSON
// form.
func jsonNumber(yamlFloat string) (string, bool) {
	s := strings.ReplaceAll(yamlFloat, "_", "")
	s = strings.TrimPrefix(s, "+")
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}
	mantissa, exponent := s, ""
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		mantissa, exponent = s[:i], s[i:]
	}
	whole, frac, hasPoint := strings.Cut(mantissa, ".")
	if whole == "" {
		whole = "0"
	}
	if trimmed := strings.TrimLeft(whole, "0"); trimmed != "" {
		whole = trimmed
	} else {
		whole = "0"
	}
	num := sign + whole
	if hasPoint && frac != "" {
		num += "." + frac
	}
	num += exponent
	return num, json.Valid([]byte(num))
}

// jsonToYAML parses JSON into a YAML node, keeping key order and the exact
// text of numbers.
func jsonToYAML(s string) (*yaml.Node, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	n, err := jsonValueToYAML(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the JSON value")
	}
	return n, nil
}

func jsonValueToYAML(dec *json.Decoder) (*yaml.Node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, _ := k.(string)
				v, err := jsonValueToYAML(dec)
				if err != nil {
					return nil, err
				}
				n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
			}
			_, err := dec.Token()
			return n, err
		}
		n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for dec.More() {
			v, err := jsonValueToYAML(dec)
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, v)
		}
		_, err := dec.Token()
		return n, err
	case json.Number:
		tag := "!!int"
		if strings.ContainsAny(string(t), ".eE") {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: string(t)}, nil
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(t)}, nil
	default:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	}
}

// InstalledApp is an entry of /api/apps/list.
type InstalledApp struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (c *Client) ListApps(ctx context.Context) ([]InstalledApp, error) {
	const path = "/api/apps/list"
	raw, err := c.get(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	resp, err := decodeResponse[struct {
		Apps []InstalledApp `json:"apps"`
	}](path, raw)
	if err != nil {
		return nil, err
	}
	return resp.Apps, nil
}

// InstallApp downloads the app package from url on the server and installs it.
func (c *Client) InstallApp(ctx context.Context, name, packageURL string) error {
	_, err := c.postForm(ctx, "/api/apps/downloadAndInstall", url.Values{
		"name": {name},
		"url":  {packageURL},
	})
	if err != nil {
		return fmt.Errorf("install app %q: %w", name, err)
	}
	return nil
}

// GetAppConfig returns the app's stored config text, or "" when it has none.
// The error matches ErrNotFound when the app is not installed. Unlike
// /api/apps/list, which fetches the App Store catalogue from the internet,
// this is answered locally.
func (c *Client) GetAppConfig(ctx context.Context, name string) (string, error) {
	const path = "/api/apps/config/get"
	raw, err := c.get(ctx, path, url.Values{"name": {name}})
	if err != nil {
		return "", fmt.Errorf("get config of app %q: %w", name, err)
	}
	resp, err := decodeResponse[struct {
		Config *string `json:"config"`
	}](path, raw)
	if err != nil {
		return "", err
	}
	if resp.Config == nil {
		return "", nil
	}
	return *resp.Config, nil
}

func (c *Client) SetAppConfig(ctx context.Context, name, config string) error {
	_, err := c.postForm(ctx, "/api/apps/config/set", url.Values{
		"name":   {name},
		"config": {config},
	})
	if err != nil {
		return fmt.Errorf("set config of app %q: %w", name, err)
	}
	return nil
}

// SameJSON reports whether a and b are equal JSON documents, ignoring
// formatting, key order and the // and /* */ comments DNS Apps accept.
// It returns false if either does not parse.
func SameJSON(a, b string) bool {
	ca, okA := canonicalJSON(stripJSONComments(a))
	cb, okB := canonicalJSON(stripJSONComments(b))
	return okA && okB && bytes.Equal(ca, cb)
}

// stripJSONComments removes // and /* */ comments outside strings, as the
// apps' JsonCommentHandling.Skip parser does.
func stripJSONComments(s string) string {
	var out strings.Builder
	inString, escaped := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			out.WriteByte(c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return out.String()
			}
			i += end + 3
			out.WriteByte(' ')
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}

// canonicalJSON re-encodes a single JSON document with sorted keys, keeping
// numbers exactly as written.
func canonicalJSON(s string) ([]byte, bool) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	b, err := json.Marshal(v)
	return b, err == nil
}
