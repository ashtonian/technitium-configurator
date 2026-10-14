package technitium

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTokenFile(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    string
		wantErr string
	}{
		{name: "create-token file", data: "username: admin\ntokenName: sdk-token\ntoken: 4b1c2d\n", want: "4b1c2d"},
		{name: "bare token", data: "4b1c2d\n", want: "4b1c2d"},
		{name: "bare numeric token", data: "123456\n", want: "123456"},
		{name: "empty", data: "", want: ""},
		{name: "blank", data: " \n\t\n", want: ""},
		{name: "document without a token", data: "username: admin\n", want: ""},
		{name: "prose", data: "not a token at all\n", wantErr: "neither a create-token file nor a bare token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTokenFile([]byte(tt.data))
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadAPITokenFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
		return path
	}
	tokenFile := write("token.yaml", "username: admin\ntokenName: sdk-token\ntoken: 4b1c2d\n")
	emptyFile := write("empty", "")
	missingFile := filepath.Join(dir, "missing")

	tests := []struct {
		name      string
		command   string
		file      string
		wantToken string
		wantErr   string
	}{
		{name: "configure reads the file", command: "configure", file: tokenFile, wantToken: "4b1c2d"},
		{name: "export reads the file", command: "export", file: tokenFile, wantToken: "4b1c2d"},
		{name: "cluster-state reads the file", command: "cluster-state", file: tokenFile, wantToken: "4b1c2d"},
		{name: "create-token leaves it unread", command: "create-token", file: missingFile},
		{name: "change-password leaves it unread", command: "change-password", file: missingFile},
		{name: "missing file", command: "configure", file: missingFile, wantErr: "read API token file"},
		{name: "empty file", command: "configure", file: emptyFile, wantErr: "holds no token"},
		{name: "no file", command: "configure"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.APITokenFile = tt.file
			err := cfg.LoadAPITokenFile(tt.command)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, cfg.APIToken)
		})
	}
}

func TestValidateAuthentication(t *testing.T) {
	tests := []struct {
		name    string
		command string
		set     func(c *ClientConfig)
		wantErr string
	}{
		{name: "token", command: "configure", set: func(c *ClientConfig) { c.APIToken = "x" }},
		{name: "token file", command: "export", set: func(c *ClientConfig) { c.APITokenFile = "token.yaml" }},
		{name: "username and password", command: "cluster-state", set: func(c *ClientConfig) { c.Username, c.Password = "admin", "pw" }},
		{name: "nothing", command: "configure", set: func(c *ClientConfig) {}, wantErr: "needs an API token"},
		{
			name:    "token and token file",
			command: "configure",
			set:     func(c *ClientConfig) { c.APIToken, c.APITokenFile = "x", "token.yaml" },
			wantErr: "not both",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.APIURL = "http://dns-server:5380"
			tt.set(cfg)
			err := cfg.Validate(tt.command)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}
