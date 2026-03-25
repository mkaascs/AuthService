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
	"auth-service/internal/lib/log"
	"auth-service/internal/lib/refreshToken"
	"auth-service/internal/mocks"
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestService_Refresh(t *testing.T) {
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

	refreshCommand := commands.Refresh{
		RefreshToken: "refresh-token",
		ClientID:     entities.WebAppClientID,
	}

	t.Run("success", func(t *testing.T) {
		mockToken.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockToken.EXPECT().UpdateByTokenTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command tokenCommands.UpdateByToken) (*results.Update, error) {
				refreshTokenHash := refreshToken.Hash(refreshCommand.RefreshToken, secret)
				assert.Equal(t, refreshTokenHash, command.RefreshTokenHash)
				assert.Equal(t, refreshCommand.ClientID, command.ClientID)
				return &results.Update{UserID: 2}, nil
			})

		mockUser.EXPECT().GetByID(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, id int64) (*userResults.Get, error) {
				assert.Equal(t, id, int64(2))
				return &userResults.Get{
					User: entities.User{
						ID:           2,
						Login:        "mkaascs",
						PasswordHash: "password-hash",
						Role:         entities.RoleAdmin,
					},
				}, nil
			})

		mockJWT.EXPECT().Generate(gomock.Any()).
			DoAndReturn(func(command tokenCommands.Generate) (*jwtResults.Generate, error) {
				assert.Equal(t, command.UserID, int64(2))
				assert.Equal(t, command.Role, entities.RoleAdmin)
				return &jwtResults.Generate{
					Token: "access-token",
				}, nil
			})

		mockTx.EXPECT().Commit().Return(nil)
		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Refresh(context.Background(), refreshCommand)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, result.Tokens.AccessToken, "access-token")
		assert.NotEmpty(t, result.Tokens.RefreshToken)
		assert.NotEqual(t, result.Tokens.RefreshToken, refreshCommand.RefreshToken)
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		mockToken.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockToken.EXPECT().UpdateByTokenTx(gomock.Any(), mockTx, gomock.Any()).
			Return(nil, authErrors.ErrInvalidRefreshToken)

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Refresh(context.Background(), refreshCommand)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, authErrors.ErrInvalidRefreshToken)
	})

	t.Run("fail jwt generating", func(t *testing.T) {
		mockToken.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockToken.EXPECT().UpdateByTokenTx(gomock.Any(), mockTx, gomock.Any()).
			Return(&results.Update{UserID: 2}, nil)

		mockUser.EXPECT().GetByID(gomock.Any(), gomock.Any()).
			Return(&userResults.Get{
				User: entities.User{
					ID:   2,
					Role: entities.RoleAdmin,
				},
			}, nil)

		mockJWT.EXPECT().Generate(gomock.Any()).
			Return(nil, errors.New("incorrect format"))

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Refresh(context.Background(), refreshCommand)
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}
