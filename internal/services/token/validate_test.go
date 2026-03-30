package token

import (
	"auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
	"auth-service/internal/domain/entities"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/lib/log"
	"auth-service/internal/mocks"
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestService_ValidateToken(t *testing.T) {
	validParseResult := &results.Parse{
		JTI:       "jti-abc123",
		UserID:    2,
		Roles:     []string{entities.RoleAdmin},
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}

	validateCommand := commands.Validate{
		AccessToken: "some-access-token",
	}

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAccessTokenSvc := mocks.NewMockAccessToken(ctrl)
		mockAccessTokenRepo := mocks.NewMockAccessTokenRepo(ctrl)
		svc := New(mockAccessTokenSvc, mockAccessTokenRepo, log.NewPlugLogger())

		mockAccessTokenSvc.EXPECT().Parse(gomock.Any()).Return(validParseResult, nil)

		mockAccessTokenRepo.EXPECT().IsRevoked(gomock.Any(), validParseResult.JTI).
			Return(false, nil)

		result, err := svc.ValidateToken(context.Background(), validateCommand)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, validParseResult.UserID, result.UserID)
		require.Equal(t, validParseResult.Roles, result.Roles)
		require.WithinDuration(t, validParseResult.ExpiresAt, result.ExpiresAt, time.Second)
	})

	t.Run("token revoked", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAccessTokenSvc := mocks.NewMockAccessToken(ctrl)
		mockAccessTokenRepo := mocks.NewMockAccessTokenRepo(ctrl)
		svc := New(mockAccessTokenSvc, mockAccessTokenRepo, log.NewPlugLogger())

		mockAccessTokenSvc.EXPECT().Parse(gomock.Any()).Return(validParseResult, nil)

		mockAccessTokenRepo.EXPECT().IsRevoked(gomock.Any(), validParseResult.JTI).
			Return(true, nil)

		result, err := svc.ValidateToken(context.Background(), validateCommand)
		require.Nil(t, result)
		require.ErrorIs(t, err, authErrors.ErrAccessTokenRevoked)
	})

	t.Run("access token expired", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAccessTokenSvc := mocks.NewMockAccessToken(ctrl)
		mockAccessTokenRepo := mocks.NewMockAccessTokenRepo(ctrl)
		svc := New(mockAccessTokenSvc, mockAccessTokenRepo, log.NewPlugLogger())

		mockAccessTokenSvc.EXPECT().Parse(gomock.Any()).
			Return(nil, authErrors.ErrAccessTokenExpired)

		result, err := svc.ValidateToken(context.Background(), validateCommand)
		require.Nil(t, result)
		require.ErrorIs(t, err, authErrors.ErrAccessTokenExpired)
	})

	t.Run("invalid access token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAccessTokenSvc := mocks.NewMockAccessToken(ctrl)
		mockAccessTokenRepo := mocks.NewMockAccessTokenRepo(ctrl)
		svc := New(mockAccessTokenSvc, mockAccessTokenRepo, log.NewPlugLogger())

		mockAccessTokenSvc.EXPECT().Parse(gomock.Any()).
			Return(nil, authErrors.ErrInvalidAccessToken)

		result, err := svc.ValidateToken(context.Background(), validateCommand)
		require.Nil(t, result)
		require.ErrorIs(t, err, authErrors.ErrInvalidAccessToken)
	})

	t.Run("redis unavailable fail open", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAccessTokenSvc := mocks.NewMockAccessToken(ctrl)
		mockAccessTokenRepo := mocks.NewMockAccessTokenRepo(ctrl)
		svc := New(mockAccessTokenSvc, mockAccessTokenRepo, log.NewPlugLogger())

		mockAccessTokenSvc.EXPECT().Parse(gomock.Any()).Return(validParseResult, nil)

		mockAccessTokenRepo.EXPECT().IsRevoked(gomock.Any(), validParseResult.JTI).
			Return(false, errors.New("redis: connection refused"))

		result, err := svc.ValidateToken(context.Background(), validateCommand)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, validParseResult.UserID, result.UserID)
	})
}
