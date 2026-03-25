package app

import (
	grpcapp "auth-service/internal/app/grpc"
	"auth-service/internal/app/mysql"
	"auth-service/internal/config"
	"log/slog"
)

type App struct {
	GRPC  *grpcapp.App
	MySql *mysql.App
}

func New(cfg config.Config, logger *slog.Logger) *App {
	grpcApp := grpcapp.New(logger, cfg.Port)
	mysqlApp, _ := mysql.New(logger, cfg.ConnectionString)

	return &App{
		GRPC:  grpcApp,
		MySql: mysqlApp,
	}
}
