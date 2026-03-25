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
	"auth-service/internal/lib/log"
	"auth-service/internal/mocks"
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestService_Register(t *testing.T) {
	bcryptPrefix := "$2a$"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUser := mocks.NewMockUser(ctrl)
	mockToken := mocks.NewMockRefreshToken(ctrl)
	mockJWT := mocks.NewMockJWT(ctrl)
	mockTx := mocks.NewMockTx(ctrl)

	logger := log.MustLoad("local")
	cfg := config.AuthConfig{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 15 * time.Minute,
		Issuer:          "test-auth",
	}

	secret := []byte("LPKCsOO6CzbXjpFUGdgZ8EtQA+oULGU+faKC60aS1Qk=")
	authService := New(mockUser, mockToken, mockJWT, logger, cfg, secret)

	registerCommand := commands.Register{
		Base: commands.Base{
			Login:    "mkaascs",
			Password: "password123",
			ClientID: entities.WebAppClientID,
		},
	}

	t.Run("success", func(t *testing.T) {
		mockUser.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUser.EXPECT().AddTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command userCommands.Add) (*results.Add, error) {
				assert.Equal(t, command.Login, registerCommand.Login)
				assert.Contains(t, command.PasswordHash, bcryptPrefix)
				assert.Equal(t, command.Role, entities.RoleUser)
				assert.Equal(t, command.ClientID, registerCommand.ClientID)
				return &results.Add{UserID: 1}, nil
			})

		expectedExpiresAt := time.Now().Add(cfg.RefreshTokenTTL)
		mockToken.EXPECT().AddTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command tokenCommands.Add) error {
				assert.Equal(t, command.UserID, int64(1))
				assert.Equal(t, command.ClientID, registerCommand.ClientID)
				assert.WithinDuration(t, expectedExpiresAt, command.ExpiresAt, time.Second)
				return nil
			})

		mockTx.EXPECT().Rollback().Return(nil)
		mockTx.EXPECT().Commit().Return(nil)

		result, err := authService.Register(context.Background(), registerCommand)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, result.UserID, int64(1))
	})

	t.Run("user already exists", func(t *testing.T) {
		mockUser.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUser.EXPECT().AddTx(gomock.Any(), mockTx, gomock.Any()).
			Return(nil, authErrors.ErrUserAlreadyExists)

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Register(context.Background(), registerCommand)
		assert.ErrorIs(t, err, authErrors.ErrUserAlreadyExists)
		assert.Nil(t, result)
	})

	t.Run("db internal error", func(t *testing.T) {
		mockUser.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUser.EXPECT().AddTx(gomock.Any(), mockTx, gomock.Any()).
			Return(&results.Add{UserID: 1}, nil)

		mockToken.EXPECT().AddTx(gomock.Any(), mockTx, gomock.Any()).
			Return(errors.New("failed to execute db statement"))

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Register(context.Background(), registerCommand)
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}
