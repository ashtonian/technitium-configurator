//go:build e2e

package e2e

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestE2EExitCodes checks the built binary's exit codes and which stream
// carries help, usage errors and command output. It needs no server.
func TestE2EExitCodes(t *testing.T) {
	bin := buildBinary(t)
	missing := t.TempDir() + "/missing.yaml"
	for _, tt := range []struct {
		name       string
		args       []string
		env        []string
		code       int
		stdoutHas  string
		stdoutNone bool
	}{
		{name: "version", args: []string{"version"}, code: 0, stdoutHas: "technitium-configurator "},
		{name: "help", args: []string{"help"}, code: 0, stdoutHas: "Usage:"},
		{name: "command help", args: []string{"configure", "--help"}, code: 0, stdoutHas: "Usage:"},
		{name: "no command", args: nil, code: 2, stdoutNone: true},
		{name: "unknown command", args: []string{"bogus"}, code: 2, stdoutNone: true},
		{name: "unknown flag", args: []string{"export", "--bogus"}, code: 2, stdoutNone: true},
		{name: "extra arguments", args: []string{"export", "a", "b"}, code: 2, stdoutNone: true},
		{name: "version with arguments", args: []string{"version", "extra"}, code: 2, stdoutNone: true},
		{name: "invalid environment", args: []string{"configure"}, env: []string{"DNS_WAIT_TIMEOUT=soon"}, code: 1, stdoutNone: true},
		{name: "missing config file", args: []string{"configure", missing}, env: []string{"DNS_API_URL=http://127.0.0.1:1", "DNS_API_TOKEN=x"}, code: 1, stdoutNone: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(bin, tt.args...)
			cmd.Env = append([]string{"HOME=" + os.Getenv("HOME"), "PATH=" + os.Getenv("PATH")}, tt.env...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tt.code {
				t.Errorf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.code, stdout.String(), stderr.String())
			}
			if tt.stdoutHas != "" && !strings.Contains(stdout.String(), tt.stdoutHas) {
				t.Errorf("stdout lacks %q:\n%s", tt.stdoutHas, stdout.String())
			}
			if tt.stdoutNone && stdout.Len() > 0 {
				t.Errorf("stdout should be empty:\n%s", stdout.String())
			}
		})
	}
}
