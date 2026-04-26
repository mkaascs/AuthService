package auth

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/dto/auth/commands"
	tokenCommands "auth-service/internal/domain/dto/tokens/commands"
	jwtResults "auth-service/internal/domain/dto/tokens/results"
	tokenResults "auth-service/internal/domain/dto/tokens/results"
	userCommands "auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/dto/user/results"
	"auth-service/internal/domain/entities"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/domain/interfaces/services"
	"auth-service/internal/domain/interfaces/tx"
	"auth-service/internal/lib/log"
	"auth-service/internal/testutil"
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestService_Login(t *testing.T) {
	const TTL = 15 * time.Minute
	cfg := config.AuthConfig{
		AccessTokenTTL:  TTL,
		RefreshTokenTTL: TTL,
		Issuer:          "test-auth",
	}

	secret := []byte("LPKCsOO6CzbXjpFUGdgZ8EtQA+oULGU+faKC60aS1Qk=")

	loginCommand := commands.Login{
		Login:    "mkaascs",
		Password: "password123",
	}

	passwordHash := testutil.HashPassword(t, loginCommand.Password)

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.UserRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.RateLimiter.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

		mock.RateLimiter.EXPECT().Reset(gomock.Any(), gomock.Any()).Return(nil)

		mock.UserRepo.EXPECT().GetByLoginTx(gomock.Any(), mock.Tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command userCommands.GetByLogin) (*results.Get, error) {
				require.Equal(t, loginCommand.Login, command.Login)
				return &results.Get{
					User: entities.User{
						ID:           2,
						Login:        command.Login,
						PasswordHash: passwordHash,
						Roles:        []string{entities.RoleAdmin},
					},
				}, nil
			})

		mock.TokenRepo.EXPECT().UpdateByUserIDTx(gomock.Any(), mock.Tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command tokenCommands.UpdateByUserID) (*tokenResults.Update, error) {
				require.Equal(t, command.UserID, int64(2))
				require.NotEmpty(t, command.NewRefreshTokenHash)
				return &tokenResults.Update{UserID: 2}, nil
			})

		mock.AccessTokenSvc.EXPECT().Generate(gomock.Any()).
			DoAndReturn(func(command tokenCommands.Generate) (*jwtResults.Generate, error) {
				require.Equal(t, command.UserID, int64(2))
				require.Equal(t, command.Roles, []string{entities.RoleAdmin})
				return &jwtResults.Generate{
					Token: "access-token",
				}, nil
			})

		mock.Tx.EXPECT().Commit().Return(nil)
		mock.Tx.EXPECT().Rollback().Return(nil).AnyTimes()

		result, err := svc.Login(context.Background(), loginCommand)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "access-token", result.Tokens.AccessToken)
		require.NotEmpty(t, result.Tokens.RefreshToken)

		now := time.Now()
		require.WithinDuration(t, now.Add(TTL), now.Add(result.ExpiresIn), time.Second)
		require.NotNil(t, result.User)
	})

	t.Run("invalid password", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		correctPasswordHash := testutil.HashPassword(t, "correct-password")

		mock.UserRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.RateLimiter.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

		mock.UserRepo.EXPECT().GetByLoginTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(&results.Get{
				User: entities.User{
					ID:           2,
					PasswordHash: correctPasswordHash,
				},
			}, nil)

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Login(context.Background(), loginCommand)
		require.ErrorIs(t, err, authErrors.ErrInvalidPassword)
		require.Nil(t, result)
	})

	t.Run("invalid login", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.UserRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.RateLimiter.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

		mock.UserRepo.EXPECT().GetByLoginTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(nil, authErrors.ErrUserNotFound)

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Login(context.Background(), loginCommand)
		require.ErrorIs(t, err, authErrors.ErrUserNotFound)
		require.Nil(t, result)
	})

	t.Run("fail access token generating", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.UserRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.RateLimiter.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

		mock.UserRepo.EXPECT().GetByLoginTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(&results.Get{
				User: entities.User{
					ID:           2,
					Login:        loginCommand.Login,
					PasswordHash: passwordHash,
					Roles:        []string{entities.RoleAdmin},
				},
			}, nil)

		mock.TokenRepo.EXPECT().UpdateByUserIDTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(&tokenResults.Update{UserID: 2}, nil)

		mock.AccessTokenSvc.EXPECT().Generate(gomock.Any()).
			Return(nil, errors.New("incorrect format"))

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Login(context.Background(), loginCommand)
		require.Nil(t, result)
		require.Error(t, err)
	})

	t.Run("context canceled on get user", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		mock.UserRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.RateLimiter.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

		mock.UserRepo.EXPECT().GetByLoginTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(nil, context.Canceled)

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Login(ctx, loginCommand)
		require.Nil(t, result)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("context canceled on update token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		ctx, cancel := context.WithCancel(context.Background())

		mock.UserRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.RateLimiter.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

		mock.UserRepo.EXPECT().GetByLoginTx(gomock.Any(), mock.Tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command userCommands.GetByLogin) (*results.Get, error) {
				cancel()
				return &results.Get{
					User: entities.User{
						ID:           2,
						Login:        loginCommand.Login,
						PasswordHash: passwordHash,
						Roles:        []string{entities.RoleAdmin},
					},
				}, nil
			})

		mock.TokenRepo.EXPECT().UpdateByUserIDTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(nil, context.Canceled)

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Login(ctx, loginCommand)
		require.Nil(t, result)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("rate limit exceeded", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.RateLimiter.EXPECT().
			Allow(gomock.Any(), loginCommand.Login).
			Return(false, nil)

		mock.UserRepo.EXPECT().BeginTx(gomock.Any()).Times(0)

		result, err := svc.Login(context.Background(), loginCommand)
		require.Nil(t, result)
		require.ErrorIs(t, err, authErrors.ErrTooManyRequests)
	})

	t.Run("success resets rate limiter", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.RateLimiter.EXPECT().
			Allow(gomock.Any(), loginCommand.Login).
			Return(true, nil)

		mock.RateLimiter.EXPECT().
			Reset(gomock.Any(), loginCommand.Login).
			Return(nil)

		mock.UserRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)
		mock.UserRepo.EXPECT().GetByLoginTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(&results.Get{
				User: entities.User{
					ID:           2,
					Login:        loginCommand.Login,
					PasswordHash: passwordHash,
					Roles:        []string{entities.RoleAdmin},
				},
			}, nil)

		mock.TokenRepo.EXPECT().UpdateByUserIDTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(&tokenResults.Update{UserID: 2}, nil)

		mock.AccessTokenSvc.EXPECT().Generate(gomock.Any()).
			Return(&jwtResults.Generate{Token: "access-token"}, nil)

		mock.Tx.EXPECT().Commit().Return(nil)
		mock.Tx.EXPECT().Rollback().Return(nil).AnyTimes()

		result, err := svc.Login(context.Background(), loginCommand)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "access-token", result.Tokens.AccessToken)
	})

	t.Run("invalid password does not reset rate limiter", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.RateLimiter.EXPECT().
			Allow(gomock.Any(), loginCommand.Login).
			Return(true, nil)

		mock.RateLimiter.EXPECT().Reset(gomock.Any(), gomock.Any()).Times(0)

		mock.UserRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)
		mock.UserRepo.EXPECT().GetByLoginTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(&results.Get{
				User: entities.User{
					ID:           2,
					PasswordHash: testutil.HashPassword(t, "correct-password"),
				},
			}, nil)

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Login(context.Background(), loginCommand)
		require.Nil(t, result)
		require.ErrorIs(t, err, authErrors.ErrInvalidPassword)
	})
}

func newTestService(mock *testutil.AuthMocks, secret []byte, cfg config.AuthConfig) services.Auth {
	return New(ServiceArgs{
		AccessTokenSvc: mock.AccessTokenSvc,
		HmacSecret:     secret,
		Config:         cfg,
	}, RepoArgs{
		UserRepo:        mock.UserRepo,
		TokenRepo:       mock.TokenRepo,
		AccessTokenRepo: mock.AccessTokenRepo,
	}, mock.RateLimiter, log.NewPlugLogger())
}
