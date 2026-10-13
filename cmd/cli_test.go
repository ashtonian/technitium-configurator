package cmd

import (
	"bytes"
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArgs(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want Invocation
	}{
		{"version", []string{"version"}, Invocation{Command: VersionCommand}},
		{"version flag", []string{"--version"}, Invocation{Command: VersionCommand}},
		{"configure without paths", []string{"configure"}, Invocation{Command: "configure", Args: []string{}}},
		{"configure with flags and paths", []string{"configure", "--log-level", "debug", "--config=client.yaml", "a.yaml", "dir"},
			Invocation{Command: "configure", Args: []string{"a.yaml", "dir"}, LogLevel: "debug", ClientConfigPath: "client.yaml"}},
		{"export to a file", []string{"export", "out.yaml"}, Invocation{Command: "export", Args: []string{"out.yaml"}}},
		{"create-token with a token path", []string{"create-token", "-token-path", "t.yaml"},
			Invocation{Command: "create-token", Args: []string{}, TokenPath: "t.yaml"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseArgs(tt.args)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseArgsHelp(t *testing.T) {
	for _, args := range [][]string{
		{"help"}, {"-h"}, {"--help"},
		{"configure", "--help"}, {"export", "-h"}, {"cluster-state", "-help"},
	} {
		_, err := ParseArgs(args)
		assert.ErrorIs(t, err, flag.ErrHelp, "%v", args)
	}
}

func TestParseArgsUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"version", "extra"},
		{"version", "--bogus"},
		{"help", "configure"},
		{"configure", "--bogus"},
		{"configure", "--log-level"},
		{"export", "a", "b"},
		{"create-token", "x"},
		{"change-password", "x"},
		{"cluster-state", "x"},
	} {
		_, err := ParseArgs(args)
		assert.ErrorIs(t, err, ErrUsage, "%v", args)
	}
}

func TestUsageListsEveryCommandAndFlag(t *testing.T) {
	var out bytes.Buffer
	Usage(&out)
	for name := range Commands {
		assert.Contains(t, out.String(), Commands[name].Usage)
	}
	for _, want := range []string{"version", "-config", "-token-path", "-log-level", "DNS_API_URL"} {
		assert.Contains(t, out.String(), want)
	}
}
