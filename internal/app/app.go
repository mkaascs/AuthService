package app

import (
	grpcapp "auth-service/internal/app/grpc"
	"auth-service/internal/app/mysql"
	"auth-service/internal/config"
	handlers "auth-service/internal/delivery/grpc/auth"
	repo "auth-service/internal/infrastructure/mysql"
	"auth-service/internal/jwt"
	"auth-service/internal/services/auth"
	"auth-service/internal/services/token"
	"auth-service/internal/services/user"
	"encoding/base64"
	"log/slog"
	"os"
)

type App struct {
	GRPC  *grpcapp.App
	MySql *mysql.App
	log   *slog.Logger
	cfg   config.Config
}

func New(cfg config.Config, logger *slog.Logger) *App {
	grpcApp := grpcapp.New(logger, cfg.Port)

	mysql.MustMigrate(logger, cfg.DbConnectionString)
	mysqlApp, _ := mysql.New(logger, cfg.DbConnectionString)

	return &App{
		GRPC:  grpcApp,
		MySql: mysqlApp,
		log:   logger,
		cfg:   cfg,
	}
}

func (a *App) MustRegisterHandlers() {
	const fn = "app.MustRegisterHandlers"
	log := a.log.With(slog.String("fn", fn))

	secret, err := base64.StdEncoding.DecodeString(os.Getenv("HMAC_SECRET_BASE64"))
	if err != nil || len(secret) == 0 {
		log.Error("failed to load HMAC_SECRET_BASE64")
		os.Exit(1)
	}

	jwtService, err := jwt.New(a.cfg.AuthConfig)
	if err != nil {
		log.Error("failed to create JWT service")
		os.Exit(1)
	}

	if a.MySql.DB == nil {
		log.Error("DB is not initialized (do MySql.MustConnect() first)")
		os.Exit(1)
	}

	userRepo := repo.NewUserRepo(a.MySql.DB, a.log)
	tokenRepo := repo.NewRefreshTokenRepo(a.MySql.DB, a.log)

	authService := auth.New(auth.ServiceArgs{
		AccessTokens: jwtService,
		Config:       a.cfg.AuthConfig,
		HmacSecret:   secret,
	}, auth.RepoArgs{
		UserRepo:  userRepo,
		TokenRepo: tokenRepo,
	}, a.log)

	userService := user.New(userRepo, a.log)
	tokenService := token.New(jwtService, a.log)

	handlers.RegisterAuthServer(a.GRPC.Server, authService)
	handlers.RegisterUserServer(a.GRPC.Server, userService)
	handlers.RegisterTokenServer(a.GRPC.Server, tokenService)
}
