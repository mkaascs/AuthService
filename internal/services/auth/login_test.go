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

		mock.UserRepo.EXPECT().GetByLoginTx(gomock.Any(), mock.Tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command userCommands.GetByLogin) (*results.Get, error) {
				require.Equal(t, loginCommand.Login, command.Login)
				return &results.Get{
					User: entities.User{
						ID:           2,
						Login:        command.Login,
						PasswordHash: string(passwordHash),
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

		mock.AccessToken.EXPECT().Generate(gomock.Any()).
			DoAndReturn(func(command tokenCommands.Generate) (*jwtResults.Generate, error) {
				require.Equal(t, command.UserID, int64(2))
				require.Equal(t, command.Roles, []string{entities.RoleAdmin})
				return &jwtResults.Generate{
					Token: "access-token",
				}, nil
			})

		mock.Tx.EXPECT().Commit().Return(nil)
		mock.Tx.EXPECT().Rollback().Return(nil)

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

		mock.AccessToken.EXPECT().Generate(gomock.Any()).
			Return(nil, errors.New("incorrect format"))

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Login(context.Background(), loginCommand)
		require.Nil(t, result)
		require.Error(t, err)
	})
}

func newTestService(mock *testutil.AuthMocks, secret []byte, cfg config.AuthConfig) services.Auth {
	return New(ServiceArgs{
		AccessTokens: mock.AccessToken,
		HmacSecret:   secret,
		Config:       cfg,
	}, RepoArgs{
		UserRepo:  mock.UserRepo,
		TokenRepo: mock.TokenRepo,
	}, log.NewPlugLogger())
}
