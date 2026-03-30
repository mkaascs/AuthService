package auth

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/dto/auth/commands"
	tokenCommands "auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
	jwtResults "auth-service/internal/domain/dto/tokens/results"
	userResults "auth-service/internal/domain/dto/user/results"
	"auth-service/internal/domain/entities"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/domain/interfaces/tx"
	"auth-service/internal/lib/refreshToken"
	"auth-service/internal/testutil"
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestService_Refresh(t *testing.T) {
	const TTL = 15 * time.Minute
	cfg := config.AuthConfig{
		AccessTokenTTL:  TTL,
		RefreshTokenTTL: TTL,
		Issuer:          "test-auth",
	}

	secret := []byte("LPKCsOO6CzbXjpFUGdgZ8EtQA+oULGU+faKC60aS1Qk=")

	refreshCommand := commands.Refresh{
		RefreshToken: "refresh-token",
	}

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.TokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.TokenRepo.EXPECT().UpdateByTokenTx(gomock.Any(), mock.Tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command tokenCommands.UpdateByToken) (*results.Update, error) {
				refreshTokenHash := refreshToken.Hash(refreshCommand.RefreshToken, secret)
				require.Equal(t, refreshTokenHash, command.RefreshTokenHash)
				return &results.Update{UserID: 2}, nil
			})

		mock.UserRepo.EXPECT().GetByIDTx(gomock.Any(), mock.Tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, id int64) (*userResults.Get, error) {
				require.Equal(t, id, int64(2))
				return &userResults.Get{
					User: entities.User{
						ID:           2,
						Login:        "mkaascs",
						PasswordHash: "password-hash",
						Roles:        []string{entities.RoleAdmin},
					},
				}, nil
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

		result, err := svc.Refresh(context.Background(), refreshCommand)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, result.Tokens.AccessToken, "access-token")
		require.NotEmpty(t, result.Tokens.RefreshToken)
		require.NotEqual(t, result.Tokens.RefreshToken, refreshCommand.RefreshToken)

		now := time.Now()
		require.WithinDuration(t, now.Add(TTL), now.Add(result.ExpiresIn), time.Second)
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.TokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.TokenRepo.EXPECT().UpdateByTokenTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(nil, authErrors.ErrInvalidRefreshToken)

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Refresh(context.Background(), refreshCommand)
		require.Nil(t, result)
		require.ErrorIs(t, err, authErrors.ErrInvalidRefreshToken)
	})

	t.Run("fail access token generating", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.TokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.TokenRepo.EXPECT().UpdateByTokenTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(&results.Update{UserID: 2}, nil)

		mock.UserRepo.EXPECT().GetByIDTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(&userResults.Get{
				User: entities.User{
					ID:    2,
					Roles: []string{entities.RoleAdmin},
				},
			}, nil)

		mock.AccessTokenSvc.EXPECT().Generate(gomock.Any()).
			Return(nil, errors.New("incorrect format"))

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Refresh(context.Background(), refreshCommand)
		require.Error(t, err)
		require.Nil(t, result)
	})

	t.Run("context canceled on update token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		mock.TokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.TokenRepo.EXPECT().UpdateByTokenTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(nil, context.Canceled)

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Refresh(ctx, refreshCommand)
		require.Nil(t, result)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("context canceled on get user", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		ctx, cancel := context.WithCancel(context.Background())

		mock.TokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.TokenRepo.EXPECT().UpdateByTokenTx(gomock.Any(), mock.Tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command tokenCommands.UpdateByToken) (*results.Update, error) {
				cancel()
				return &results.Update{UserID: 2}, nil
			})

		mock.UserRepo.EXPECT().GetByIDTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(nil, context.Canceled)

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Refresh(ctx, refreshCommand)
		require.Nil(t, result)
		require.ErrorIs(t, err, context.Canceled)
	})
}
