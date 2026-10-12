package technitium

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func load(y string) (*Config, error) {
	return LoadConfig(Source{Name: "test.yaml", Data: []byte(y)})
}

func TestLoadConfigRejectsUnknownKeys(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "top level",
			yaml: "recrods: []\n",
			want: "field recrods not found",
		},
		{
			name: "obsolete setting",
			yaml: "dnsSettings:\n  qpmLimitRequests: 0\n",
			want: "field qpmLimitRequests not found",
		},
		{
			name: "zone field",
			yaml: "zones:\n  - zone: example.test\n    type: Primary\n    catalogue: x\n",
			want: "field catalogue not found",
		},
		{
			name: "record field",
			yaml: "records:\n  - domain: www.example.test\n    type: A\n    ipAdress: 192.0.2.1\n",
			want: `unknown record field "ipAdress"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(tt.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestLoadConfigRecordFields(t *testing.T) {
	cfg, err := load(`
records:
  - domain: www.example.test
    type: A
    ipAddress: 192.0.2.1
    ttl: 123
    comments: web
    expiryTtl: 600
  - name: alias.example.test
    type: A
    value: 192.0.2.2
    ttl: 0
  - domain: example.test
    type: CAA
    flags: 0
    tag: issue
    value: letsencrypt.org
`)
	require.NoError(t, err)
	require.Len(t, cfg.Records, 3)

	web := cfg.Records[0]
	require.NotNil(t, web.TTL)
	assert.Equal(t, 123, *web.TTL)
	require.NotNil(t, web.Comments)
	assert.Equal(t, "web", *web.Comments)
	require.NotNil(t, web.ExpiryTTL)
	assert.Equal(t, 600, *web.ExpiryTTL)

	form, err := jsonToFormValues(web)
	require.NoError(t, err)
	assert.Equal(t, "123", form.Get("ttl"))
	assert.Equal(t, "web", form.Get("comments"))
	assert.Equal(t, "600", form.Get("expiryTtl"))

	alias := cfg.Records[1]
	assert.Equal(t, "alias.example.test", alias.Domain)
	assert.Equal(t, "192.0.2.2", alias.IPAddress)
	assert.Empty(t, alias.Value)
	require.NotNil(t, alias.TTL)
	assert.Equal(t, 0, *alias.TTL)

	caa := cfg.Records[2]
	assert.Equal(t, "letsencrypt.org", caa.Value)
	assert.Empty(t, caa.IPAddress)
}

func TestLoadConfigRejectsConflictingAliases(t *testing.T) {
	_, err := load("records:\n  - domain: a.example.test\n    name: b.example.test\n    type: A\n    ipAddress: 192.0.2.1\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both domain and its alias name")

	_, err = load("records:\n  - domain: a.example.test\n    type: A\n    ipAddress: 192.0.2.1\n    value: 192.0.2.2\n")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both ipAddress and its alias value")
}

func TestSettingsSendExplicitZeroValues(t *testing.T) {
	cfg, err := load(`
dnsSettings:
  enableBlocking: false
  dnssecValidation: false
  cacheMaximumEntries: 0
  cacheMinimumRecordTtl: 0
  forwarders: []
  defaultResponsiblePerson: ""
`)
	require.NoError(t, err)

	body, err := json.Marshal(cfg.DNSSettings)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"enableBlocking": false,
		"dnssecValidation": false,
		"cacheMaximumEntries": 0,
		"cacheMinimumRecordTtl": 0,
		"forwarders": [],
		"defaultResponsiblePerson": ""
	}`, string(body))
}

func TestLoadConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []string
	}{
		{
			name: "tsig secret required",
			yaml: "dnsSettings:\n  tsigKeys:\n    - keyName: k\n      algorithmName: hmac-sha256\n",
			want: []string{"sharedSecret is required"},
		},
		{
			name: "duplicate tsig names differ only in case",
			yaml: "dnsSettings:\n  tsigKeys:\n    - {keyName: K, algorithmName: hmac-sha256, sharedSecret: a}\n    - {keyName: k, algorithmName: hmac-sha256, sharedSecret: b}\n",
			want: []string{"tsigKeys[1] (k): duplicate keyName"},
		},
		{
			name: "zone type and duplicates",
			yaml: "zones:\n  - {zone: example.test, type: Master}\n  - {zone: Example.Test., type: Primary}\n",
			want: []string{`type "Master"`, "zones[1] (Example.Test.): duplicate zone"},
		},
		{
			name: "catalog on a type that cannot be a member",
			yaml: "zones:\n  - {zone: cat.example.test, type: Catalog, catalog: other.example.test}\n",
			want: []string{"cannot be a catalog member"},
		},
		{
			name: "record and app requirements",
			yaml: "records:\n  - {type: A}\napps:\n  - {name: NO DATA, url: 'ftp://example.test/x.zip'}\n",
			want: []string{"domain (or name) is required", "url must be an http or https URL"},
		},
		{
			name: "cluster mode",
			yaml: "cluster:\n  mode: leader\n",
			want: []string{`cluster.mode "leader"`},
		},
		{
			name: "secondary needs primary details",
			yaml: "cluster:\n  mode: secondary\n  nodeIPs: 10.0.0.2\n",
			want: []string{"cluster.primaryURL is required", "cluster.primaryPassword is required"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(tt.yaml)
			require.Error(t, err)
			for _, w := range tt.want {
				assert.Contains(t, err.Error(), w)
			}
		})
	}
}

func TestLoadConfigEmpty(t *testing.T) {
	_, err := LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no YAML documents")
}
