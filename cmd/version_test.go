package cmd

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveBuild(t *testing.T) {
	checkout := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "6883819"},
			{Key: "vcs.time", Value: "2026-10-13T05:39:23Z"},
		},
	}
	tests := []struct {
		name    string
		ldflags Build
		info    *debug.BuildInfo
		want    Build
	}{
		{
			name:    "release build",
			ldflags: Build{Version: "3.0.1", Commit: "6883819", Date: "2026-10-13T05:39:23Z"},
			info:    &debug.BuildInfo{Main: debug.Module{Version: "v3.0.2"}},
			want:    Build{Version: "3.0.1", Commit: "6883819", Date: "2026-10-13T05:39:23Z"},
		},
		{
			name: "go install module@version",
			info: &debug.BuildInfo{Main: debug.Module{Version: "v3.0.1"}},
			want: Build{Version: "3.0.1", Commit: "unknown", Date: "unknown"},
		},
		{
			name: "build from a checkout",
			info: checkout,
			want: Build{Version: "dev", Commit: "6883819", Date: "unknown"},
		},
		{
			name: "no build information",
			want: Build{Version: "dev", Commit: "unknown", Date: "unknown"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveBuild(tt.ldflags, tt.info))
		})
	}
}
