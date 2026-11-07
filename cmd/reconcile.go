package cmd

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/ashtonian/technitium-configurator/v3/pkg/technitium"
)

func runReconcile(ctx context.Context, cfg *technitium.ClientConfig, paths []string, stdout io.Writer) error {
	client, err := technitium.NewClient(cfg)
	if err != nil {
		return err
	}
	_ = client.Close(ctx)
	return reconcile(ctx, cfg, func(pass context.Context) error {
		current := *cfg
		if current.APITokenFile != "" {
			current.APIToken = ""
		}
		if err := current.LoadAPITokenFile("reconcile"); err != nil {
			return err
		}
		return runConfigure(pass, &current, paths, stdout)
	}, sleepCtx)
}

func reconcile(ctx context.Context, cfg *technitium.ClientConfig, apply func(context.Context) error, wait func(context.Context, time.Duration) error) error {
	for ctx.Err() == nil {
		pass, cancel := context.WithTimeout(ctx, cfg.ReconcileTimeout)
		err := apply(pass)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			slog.Error("Reconciliation failed; retrying after interval", "error", err)
		}
		if err := wait(ctx, cfg.ReconcileInterval); err != nil {
			return nil
		}
	}
	return nil
}
