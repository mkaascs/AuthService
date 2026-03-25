package mysql

import (
	sloglib "auth-service/internal/lib/log/slog"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log/slog"
	"os"
)

type App struct {
	db     *sql.DB
	logger *slog.Logger
}

func (a *App) MustConnect() {
	if err := a.Connect(); err != nil {
		a.logger.Error("failed to connect mysql app", sloglib.Error(err))
		os.Exit(1)
	}
}

func (a *App) Connect() error {
	const fn = "app.mysql.app.Connect"
	log := a.logger.With(slog.String("fn", fn), slog.String("driver", "mysql"))

	if err := a.db.Ping(); err != nil {
		log.Error("failed to ping database connection", sloglib.Error(err))
		return fmt.Errorf("%s: failed to ping database connection: %w", fn, err)
	}

	log.Info("successfully connected to database")
	return nil
}

func (a *App) Close() error {
	const fn = "app.mysql.app.Close"
	log := a.logger.With(slog.String("fn", fn), slog.String("driver", "mysql"))

	if err := a.db.Close(); err != nil {
		log.Error("failed to close database", sloglib.Error(err))
		return fmt.Errorf("%s: failed to close database connection: %w", fn, err)
	}

	log.Info("successfully closed database")
	return nil
}

func New(logger *slog.Logger, connectionString string) (*App, error) {
	const fn = "app.mysql.app.New"
	log := logger.With(slog.String("fn", fn), slog.String("driver", "mysql"))

	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		log.Error("failed to open database connection", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to open database connection: %w", fn, err)
	}

	return &App{
		db:     db,
		logger: logger,
	}, err
}
