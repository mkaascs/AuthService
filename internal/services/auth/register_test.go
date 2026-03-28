package auth

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/dto/auth/commands"
	tokenCommands "auth-service/internal/domain/dto/tokens/commands"
	userCommands "auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/dto/user/results"
	"auth-service/internal/domain/entities"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/domain/interfaces/tx"
	"auth-service/internal/testutil"
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestService_Register(t *testing.T) {
	const bcryptPrefix = "$2a$"
	const TTL = 15 * time.Minute
	cfg := config.AuthConfig{
		AccessTokenTTL:  TTL,
		RefreshTokenTTL: TTL,
		Issuer:          "test-auth",
	}

	secret := []byte("LPKCsOO6CzbXjpFUGdgZ8EtQA+oULGU+faKC60aS1Qk=")

	registerCommand := commands.Register{
		Login:    "mkaascs",
		Email:    "email@gmail.com",
		Password: "password123",
	}

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.UserRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.UserRepo.EXPECT().AddTx(gomock.Any(), mock.Tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command userCommands.Add) (*results.Add, error) {
				require.Equal(t, command.User.Login, registerCommand.Login)
				require.Contains(t, command.User.PasswordHash, bcryptPrefix)
				require.Equal(t, command.User.Roles, []string{entities.RoleUser})
				require.Equal(t, command.User.Email, registerCommand.Email)
				return &results.Add{UserID: 1}, nil
			})

		expectedExpiresAt := time.Now().Add(cfg.RefreshTokenTTL)
		mock.TokenRepo.EXPECT().AddTx(gomock.Any(), mock.Tx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command tokenCommands.Add) error {
				require.Equal(t, command.UserID, int64(1))
				require.WithinDuration(t, expectedExpiresAt, command.ExpiresAt, time.Second)
				return nil
			})

		mock.Tx.EXPECT().Rollback().Return(nil)
		mock.Tx.EXPECT().Commit().Return(nil)

		result, err := svc.Register(context.Background(), registerCommand)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, result.UserID, int64(1))
	})

	t.Run("user already exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.UserRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.UserRepo.EXPECT().AddTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(nil, authErrors.ErrUserAlreadyExists)

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Register(context.Background(), registerCommand)
		require.ErrorIs(t, err, authErrors.ErrUserAlreadyExists)
		require.Nil(t, result)
	})

	t.Run("db internal error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		mock.UserRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.UserRepo.EXPECT().AddTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(&results.Add{UserID: 1}, nil)

		mock.TokenRepo.EXPECT().AddTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(errors.New("failed to execute db statement"))

		mock.Tx.EXPECT().Rollback().Return(nil)

		result, err := svc.Register(context.Background(), registerCommand)
		require.Error(t, err)
		require.Nil(t, result)
	})
}
