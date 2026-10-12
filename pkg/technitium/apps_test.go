package technitium

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestAppConfigJSONPassesThrough(t *testing.T) {
	var app AppConfig
	require.NoError(t, yaml.Unmarshal([]byte(`
name: Advanced Forwarding
url: https://download.technitium.com/dns/apps/AdvancedForwardingApp-v5.2.zip
config:
  appPreference: 0
  enableForwarding: true
  forwarders:
    - name: quad9
      dnssecValidation: false
      forwarderAddresses: ["https://dns.quad9.net/dns-query"]
  futureField: {nested: [1, 2]}
  networkGroupMap:
    "0.0.0.0/0": default
`), &app))

	config, ok, err := app.ConfigJSON()
	require.NoError(t, err)
	require.True(t, ok)
	assert.JSONEq(t, `{
		"appPreference": 0,
		"enableForwarding": true,
		"forwarders": [{"name": "quad9", "dnssecValidation": false, "forwarderAddresses": ["https://dns.quad9.net/dns-query"]}],
		"futureField": {"nested": [1, 2]},
		"networkGroupMap": {"0.0.0.0/0": "default"}
	}`, config)
}

func TestAppConfigJSONTopLevelArray(t *testing.T) {
	var app AppConfig
	require.NoError(t, yaml.Unmarshal([]byte("name: Block Page\nurl: u\nconfig:\n  - name: default\n    enableWebServer: true\n"), &app))
	config, ok, err := app.ConfigJSON()
	require.NoError(t, err)
	require.True(t, ok)
	assert.JSONEq(t, `[{"name": "default", "enableWebServer": true}]`, config)
}

func TestAppConfigJSONOmitted(t *testing.T) {
	var app AppConfig
	require.NoError(t, yaml.Unmarshal([]byte("name: NO DATA\nurl: u\n"), &app))
	_, ok, err := app.ConfigJSON()
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSameJSON(t *testing.T) {
	assert.True(t, SameJSON(`{"a": 1, "b": [true, null]}`, "{\n  \"b\": [true, null],\n  \"a\": 1\n}"))
	assert.False(t, SameJSON(`{"a": 1}`, `{"a": 2}`))
	assert.True(t, SameJSON("{\n  \"a\": 1, // why\n  /* block */ \"b\": \"//not a comment\"\n}", `{"b": "//not a comment", "a": 1}`), "comments are ignored, as the apps ignore them")
	assert.False(t, SameJSON(`{"a": 1} {"b": 2}`, `{"a": 1}`), "a second document is not ignored")
	assert.False(t, SameJSON("", `{}`))
}

// JSON assertions compare numbers as float64, so these compare text.
func TestAppConfigJSONKeepsNumbersExact(t *testing.T) {
	var app AppConfig
	require.NoError(t, yaml.Unmarshal([]byte(`
name: X
url: https://example.test/x.zip
config:
  big: 9007199254740993
  hex: 0x1F
  ratio: 1.10
  exp: 1e3
  list: [1, true, null, "2"]
`), &app))
	config, ok, err := app.ConfigJSON()
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, `{"big":9007199254740993,"hex":31,"ratio":1.10,"exp":1e3,"list":[1,true,null,"2"]}`, config)
}

func TestExportedAppConfigRoundTrips(t *testing.T) {
	server := `{"z": 9007199254740993, "a": [1.5, {"k": null}], "s": "x"}`
	n, err := jsonToYAML(server)
	require.NoError(t, err)
	out, err := yaml.Marshal(n)
	require.NoError(t, err)

	var app AppConfig
	require.NoError(t, yaml.Unmarshal(append([]byte("name: X\nconfig:\n"), indent(out)...), &app))
	config, ok, err := app.ConfigJSON()
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, `{"z":9007199254740993,"a":[1.5,{"k":null}],"s":"x"}`, config)
	assert.True(t, SameJSON(server, config))
	assert.False(t, SameJSON(`{"z": 9007199254740992}`, config), "integers differing past float64 precision are different")
}

func indent(b []byte) []byte {
	var out []byte
	for _, line := range bytes.SplitAfter(b, []byte("\n")) {
		if len(line) > 0 {
			out = append(append(out, "  "...), line...)
		}
	}
	return out
}

func TestAppConfigJSONYAMLFeatures(t *testing.T) {
	tests := []struct {
		name, config, want string
	}{
		{"merge keys", "base: &b {x: 1, y: 2}\n  c:\n    <<: *b\n    y: 3", `{"base":{"x":1,"y":2},"c":{"y":3,"x":1}}`},
		{"merge sequence, earlier wins", "a: &a {k: 1}\n  b: &b {k: 2, m: 2}\n  c:\n    <<: [*a, *b]", `{"a":{"k":1},"b":{"k":2,"m":2},"c":{"k":1,"m":2}}`},
		{"decimal spellings", "a: +9007199254740993.0\n  b: 1_000.5\n  c: .5\n  d: -0.25e+3", `{"a":9007199254740993.0,"b":1000.5,"c":0.5,"d":-0.25e+3}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var app AppConfig
			require.NoError(t, yaml.Unmarshal([]byte("name: X\nconfig:\n  "+tt.config+"\n"), &app))
			got, ok, err := app.ConfigJSON()
			require.NoError(t, err)
			require.True(t, ok)
			assert.Equal(t, tt.want, got)
		})
	}

	for name, config := range map[string]string{
		"duplicate keys": "a: 1\n  a: 2",
		"alias cycle":    "a: &x [*x]",
		"alias bomb":     "a: &a [x,x,x,x,x,x,x,x,x]\n  b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n  c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n  d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n  e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n  f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\n  g: [*f,*f,*f,*f,*f,*f,*f,*f,*f]",
		"infinity":       "a: .inf",
	} {
		t.Run(name, func(t *testing.T) {
			var app AppConfig
			require.NoError(t, yaml.Unmarshal([]byte("name: X\nconfig:\n  "+config+"\n"), &app))
			_, _, err := app.ConfigJSON()
			assert.Error(t, err)
		})
	}
}

// Numbers beyond float64 and int64 survive export and reload as numbers.
func TestExportedAppConfigOutOfRangeNumbers(t *testing.T) {
	server := `{"precise":1e400,"huge":123456789012345678901234567890,"neg":-1E-400}`
	n, err := jsonToYAML(server)
	require.NoError(t, err)
	out, err := yaml.Marshal(n)
	require.NoError(t, err)
	t.Logf("exported:\n%s", out)

	var app AppConfig
	require.NoError(t, yaml.Unmarshal(append([]byte("name: X\nconfig:\n"), indent(out)...), &app))
	config, ok, err := app.ConfigJSON()
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, `{"precise":1e400,"huge":123456789012345678901234567890,"neg":-1E-400}`, config)
}
