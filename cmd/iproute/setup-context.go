package main

import (
	"context"

	"github.com/thataway/common-lib/logger"
	"github.com/thataway/common-lib/pkg/signals"
	"github.com/thataway/iproute/internal/app"
	"go.uber.org/zap"
)

func setupContext() {
	ctx, cancel := context.WithCancel(context.Background())
	signals.WhenSignalExit(func() error {
		logger.SetLevel(zap.InfoLevel)
		logger.Info(ctx, "caught application stop signal")
		cancel()
		return nil
	})
	app.SetContext(ctx)
}
