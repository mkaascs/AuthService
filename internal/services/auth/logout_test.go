package auth

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/dto/auth/commands"
	tokenCommands "auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
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

func TestService_Logout(t *testing.T) {
	const TTL = 15 * time.Minute
	cfg := config.AuthConfig{
		AccessTokenTTL:  TTL,
		RefreshTokenTTL: TTL,
		Issuer:          "test-auth",
	}

	secret := []byte("LPKCsOO6CzbXjpFUGdgZ8EtQA+oULGU+faKC60aS1Qk=")

	logoutCommand := commands.Logout{
		RefreshToken: "refresh-token",
		AccessToken:  "access-token",
	}

	validClaims := &results.Parse{
		JTI:       "jti-abc123",
		UserID:    1,
		ExpiresAt: time.Now().Add(TTL),
	}

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.AccessTokenSvc.EXPECT().Parse(gomock.Any()).Return(validClaims, nil)

		mock.TokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.TokenRepo.EXPECT().DeleteByTokenTx(gomock.Any(), mock.Tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command tokenCommands.DeleteByToken) (*results.Delete, error) {
				require.Equal(t, refreshToken.Hash(logoutCommand.RefreshToken, secret), command.RefreshTokenHash)
				return &results.Delete{UserID: 1}, nil
			})

		mock.Tx.EXPECT().Commit().Return(nil)
		mock.Tx.EXPECT().Rollback().Return(nil).AnyTimes()

		mock.AccessTokenRepo.EXPECT().Revoke(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, cmd tokenCommands.Revoke) error {
				require.Equal(t, validClaims.JTI, cmd.JTI)
				require.Positive(t, cmd.TTL)
				return nil
			})

		err := svc.Logout(context.Background(), logoutCommand)
		require.NoError(t, err)
	})

	t.Run("success with expired access token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.AccessTokenSvc.EXPECT().Parse(gomock.Any()).
			Return(nil, authErrors.ErrAccessTokenExpired)

		mock.TokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.TokenRepo.EXPECT().DeleteByTokenTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(&results.Delete{UserID: 1}, nil)

		mock.Tx.EXPECT().Commit().Return(nil)
		mock.Tx.EXPECT().Rollback().Return(nil).AnyTimes()

		err := svc.Logout(context.Background(), logoutCommand)
		require.NoError(t, err)
	})

	t.Run("success when redis revoke fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.AccessTokenSvc.EXPECT().Parse(gomock.Any()).Return(validClaims, nil)

		mock.TokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.TokenRepo.EXPECT().DeleteByTokenTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(&results.Delete{UserID: 1}, nil)

		mock.Tx.EXPECT().Commit().Return(nil)
		mock.Tx.EXPECT().Rollback().Return(nil).AnyTimes()

		mock.AccessTokenRepo.EXPECT().Revoke(gomock.Any(), gomock.Any()).
			Return(errors.New("redis: connection refused"))

		err := svc.Logout(context.Background(), logoutCommand)
		require.NoError(t, err)
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.AccessTokenSvc.EXPECT().Parse(gomock.Any()).Return(validClaims, nil)

		mock.TokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.TokenRepo.EXPECT().DeleteByTokenTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(nil, authErrors.ErrInvalidRefreshToken)

		mock.Tx.EXPECT().Rollback().Return(nil).AnyTimes()

		err := svc.Logout(context.Background(), logoutCommand)
		require.ErrorIs(t, err, authErrors.ErrInvalidRefreshToken)
	})

	t.Run("context canceled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		mock.AccessTokenSvc.EXPECT().Parse(gomock.Any()).Return(validClaims, nil)

		mock.TokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.TokenRepo.EXPECT().DeleteByTokenTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(nil, context.Canceled)

		mock.Tx.EXPECT().Rollback().Return(nil).AnyTimes()

		err := svc.Logout(ctx, logoutCommand)
		require.ErrorIs(t, err, context.Canceled)
	})
}
