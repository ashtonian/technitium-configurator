package technitium

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExportAppsStoreNotes(t *testing.T) {
	const installed = `{"status":"ok","response":{"apps":[{"name":"Split Horizon","version":"9"},{"name":"Private App","version":"1"}]}}`
	const config = `{"status":"ok","response":{"config":null}}`

	t.Run("store unreachable", func(t *testing.T) {
		c, _ := newTestServer(t, func(path string) string {
			switch path {
			case "/api/apps/list":
				return installed
			case "/api/apps/listStoreApps":
				return `{"status":"error","errorMessage":"Name or service not known"}`
			}
			return config
		})
		cfg := &Config{}
		notes, err := exportApps(context.Background(), c, cfg)
		require.NoError(t, err)
		require.Len(t, notes, 1)
		assert.Contains(t, notes[0], "could not be read")
		assert.Contains(t, notes[0], "Split Horizon, Private App")
		assert.NotContains(t, strings.Join(notes, "\n"), "is not in the App Store")
		require.Len(t, cfg.Apps, 2)
		assert.Empty(t, cfg.Apps[0].Url)
	})

	t.Run("store read", func(t *testing.T) {
		c, _ := newTestServer(t, func(path string) string {
			switch path {
			case "/api/apps/list":
				return installed
			case "/api/apps/listStoreApps":
				return `{"status":"ok","response":{"storeApps":[{"name":"Split Horizon","version":"10","url":"https://download.technitium.com/dns/apps/SplitHorizonApp-v10.zip"}]}}`
			}
			return config
		})
		cfg := &Config{}
		notes, err := exportApps(context.Background(), c, cfg)
		require.NoError(t, err)
		assert.Equal(t, []string{
			"App Split Horizon: v9 is installed; the url is the store's current v10.",
			"App Private App is not in the App Store, so it has no url; add one to install it on another server.",
		}, notes)
		require.Len(t, cfg.Apps, 2)
		assert.Equal(t, "https://download.technitium.com/dns/apps/SplitHorizonApp-v10.zip", cfg.Apps[0].Url)
		assert.Empty(t, cfg.Apps[1].Url)
	})
}
