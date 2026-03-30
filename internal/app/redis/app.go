package redis

import (
	"auth-service/internal/config"
	sloglib "auth-service/internal/lib/log/slog"
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"log/slog"
	"os"
)

type App struct {
	Client *redis.Client
	logger *slog.Logger
}

func New(config config.RedisConfig, logger *slog.Logger) *App {
	return &App{
		Client: redis.NewClient(&redis.Options{
			Addr:         config.Host,
			Password:     config.Password,
			DB:           config.DB,
			DialTimeout:  config.DialTimeout,
			ReadTimeout:  config.Timeout,
			WriteTimeout: config.Timeout,
			MaxRetries:   config.MaxRetries,
		}),

		logger: logger,
	}
}

func (a *App) MustConnect() {
	if err := a.Connect(); err != nil {
		os.Exit(1)
	}
}

func (a *App) Connect() error {
	const fn = "app.redis.App.Connect"
	log := a.logger.With(slog.String("fn", fn), slog.String("driver", "redis"))

	if err := a.Client.Ping(context.Background()).Err(); err != nil {
		log.Error("failed to connect to redis db", sloglib.Error(err))
		return fmt.Errorf("%s: failed to connect to redis db %w", fn, err)
	}

	log.Info("successfully connected to redis db")
	return nil
}

func (a *App) Close() error {
	const fn = "app.redis.App.Close"
	log := a.logger.With(slog.String("fn", fn), slog.String("driver", "redis"))

	if err := a.Client.Close(); err != nil {
		log.Error("failed to close redis db", sloglib.Error(err))
		return fmt.Errorf("%s: failed to close redis db %w", fn, err)
	}

	log.Info("successfully closed redis db")
	return nil
}
