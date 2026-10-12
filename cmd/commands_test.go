package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ashtonian/technitium-configurator/v3/pkg/technitium"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFilePrivate(t *testing.T) {
	t.Run("new file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token.yaml")
		require.NoError(t, writeFilePrivate(path, []byte("secret")))
		assertPrivateFile(t, path, "secret")
	})

	t.Run("existing readable file is made private", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token.yaml")
		require.NoError(t, os.WriteFile(path, []byte("old token that is longer"), 0o644))
		require.NoError(t, writeFilePrivate(path, []byte("new")))
		assertPrivateFile(t, path, "new")
	})

	t.Run("existing file in a read-only directory", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "token.yaml")
		require.NoError(t, os.WriteFile(path, []byte("old token that is longer"), 0o600))
		require.NoError(t, os.Chmod(dir, 0o555))
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		if f, err := os.CreateTemp(dir, "probe"); err == nil {
			_ = f.Close()
			t.Skip("directory permissions are not enforced for this user")
		}
		require.NoError(t, writeFilePrivate(path, []byte("new")))
		assertPrivateFile(t, path, "new")
	})
}

func assertPrivateFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, want, string(got))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestRunCommandUsageErrors(t *testing.T) {
	cfg := technitium.DefaultConfig()
	for _, tt := range []struct {
		command string
		args    []string
	}{
		{"bogus", nil},
		{"export", []string{"a", "b"}},
		{"create-token", []string{"x"}},
		{"cluster-state", []string{"x"}},
	} {
		err := RunCommand(context.Background(), cfg, tt.command, tt.args)
		assert.ErrorIs(t, err, ErrUsage, "%s %v", tt.command, tt.args)
	}
}
