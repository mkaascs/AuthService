package mysql

import (
	sloglib "auth-service/internal/lib/log/slog"
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"log/slog"
	"os"
)

type App struct {
	DB     *sql.DB
	logger *slog.Logger
}

func New(logger *slog.Logger, connectionString string) (*App, error) {
	const fn = "app.mysql.App.New"
	log := logger.With(slog.String("fn", fn), slog.String("driver", "mysql"))

	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		log.Error("failed to open database connection", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to open database connection: %w", fn, err)
	}

	return &App{
		DB:     db,
		logger: logger,
	}, err
}

func (a *App) MustConnect() {
	if err := a.Connect(); err != nil {
		os.Exit(1)
	}
}

func (a *App) Connect() error {
	const fn = "app.mysql.App.Connect"
	log := a.logger.With(slog.String("fn", fn), slog.String("driver", "mysql"))

	if err := a.DB.Ping(); err != nil {
		log.Error("failed to ping database connection", sloglib.Error(err))
		return fmt.Errorf("%s: failed to ping database connection: %w", fn, err)
	}

	log.Info("successfully connected to database")
	return nil
}

func (a *App) Close() error {
	const fn = "app.mysql.App.Close"
	log := a.logger.With(slog.String("fn", fn), slog.String("driver", "mysql"))

	if err := a.DB.Close(); err != nil {
		log.Error("failed to close database", sloglib.Error(err))
		return fmt.Errorf("%s: failed to close database connection: %w", fn, err)
	}

	log.Info("successfully closed database")
	return nil
}

func MustMigrate(logger *slog.Logger, connectionString string) {
	if err := Migrate(logger, connectionString); err != nil {
		os.Exit(1)
	}
}

func Migrate(logger *slog.Logger, connectionString string) error {
	const fn = "app.mysql.App.Migrate"
	log := logger.With(slog.String("fn", fn), slog.String("driver", "mysql"))

	mgr, err := migrate.New("file://migrations", "mysql://"+connectionString)
	if err != nil {
		log.Error("failed to open migrations", sloglib.Error(err))
		return fmt.Errorf("%s: failed to open migrations: %w", fn, err)
	}

	defer func(mgr *migrate.Migrate) {
		if err, _ := mgr.Close(); err != nil {
			log.Error("failed to close migrations", sloglib.Error(err))
		}
	}(mgr)

	if err := mgr.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Error("failed to run migrations", sloglib.Error(err))
		return fmt.Errorf("%s: failed to run migrations: %w", fn, err)
	}

	log.Info("successfully migrated database")
	return nil
}
