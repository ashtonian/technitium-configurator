package technitium

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClusterOptionsLogValue(t *testing.T) {
	tests := []struct {
		name string
		opts ClusterOptionsRequest
		want string
	}{
		{
			name: "only the options set",
			opts: ClusterOptionsRequest{ConfigRefreshIntervalSecs: 60},
			want: "options.configRefreshIntervalSeconds=60\n",
		},
		{
			name: "every option",
			opts: ClusterOptionsRequest{
				HeartbeatRefreshIntervalSecs: 15,
				HeartbeatRetryIntervalSecs:   10,
				ConfigRefreshIntervalSecs:    60,
				ConfigRetryIntervalSecs:      30,
			},
			want: "options.configRefreshIntervalSeconds=60 options.configRetryIntervalSeconds=30 " +
				"options.heartbeatRefreshIntervalSeconds=15 options.heartbeatRetryIntervalSeconds=10\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			drop := func(_ []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey || a.Key == slog.LevelKey || a.Key == slog.MessageKey {
					return slog.Attr{}
				}
				return a
			}
			slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: drop})).Info("", "options", tt.opts)
			assert.Equal(t, tt.want, buf.String())
		})
	}
}
