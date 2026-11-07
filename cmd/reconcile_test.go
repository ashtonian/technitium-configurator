package cmd

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ashtonian/technitium-configurator/v3/pkg/technitium"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReconcileRetriesAndCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := technitium.DefaultConfig()
	passes, waits := 0, 0
	err := reconcile(ctx, cfg, func(pass context.Context) error {
		passes++
		_, bounded := pass.Deadline()
		assert.True(t, bounded)
		if passes == 1 {
			return errors.New("transient server failure")
		}
		cancel()
		return nil
	}, func(wait context.Context, interval time.Duration) error {
		waits++
		assert.Equal(t, cfg.ReconcileInterval, interval)
		return wait.Err()
	})
	require.NoError(t, err)
	assert.Equal(t, 2, passes)
	assert.Equal(t, 1, waits)
}

func TestReconcileBoundsEachPass(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cfg := technitium.DefaultConfig()
		passes := 0
		err := reconcile(ctx, cfg, func(pass context.Context) error {
			passes++
			if passes == 1 {
				<-pass.Done()
				require.ErrorIs(t, pass.Err(), context.DeadlineExceeded)
				return pass.Err()
			}
			cancel()
			return nil
		}, sleepCtx)
		require.NoError(t, err)
		assert.Equal(t, 2, passes)
	})
}

func TestReconcileInvalidDeadlines(t *testing.T) {
	for _, field := range []string{"interval", "timeout"} {
		t.Run(field, func(t *testing.T) {
			cfg := technitium.DefaultConfig()
			cfg.APIURL = "http://example.test"
			cfg.APIToken = "token"
			if field == "interval" {
				cfg.ReconcileInterval = 0
			} else {
				cfg.ReconcileTimeout = 0
			}
			require.ErrorContains(t, cfg.Validate("reconcile"), "must be greater than 0")
		})
	}
}
