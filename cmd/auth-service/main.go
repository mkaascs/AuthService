package main

import (
	"auth-service/internal/app"
	"auth-service/internal/config"
	myLog "auth-service/internal/lib/log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg := config.MustLoad()
	logger := myLog.MustLoad(cfg.Env)

	logger.Info("application auth-service is starting",
		slog.String("env", cfg.Env))

	application := app.New(*cfg, logger)

	application.MySql.MustConnect()
	go application.GRPC.MustRun()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop

	application.GRPC.Stop()
	_ = application.MySql.Close()

	logger.Info("application auth-service stopped")
}
