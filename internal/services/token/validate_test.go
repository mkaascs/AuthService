package token

import (
	"auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
	"auth-service/internal/domain/entities"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/lib/log"
	"auth-service/internal/mocks"
	"context"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestService_ValidateToken(t *testing.T) {
	tests := []struct {
		name          string
		accessToken   string
		mockError     error
		expectedError error
	}{
		{
			name:          "success validated",
			accessToken:   "correct-access-token",
			mockError:     nil,
			expectedError: nil,
		},
		{
			name:          "access token expired",
			accessToken:   "expired-access-token",
			mockError:     authErrors.ErrAccessTokenExpired,
			expectedError: authErrors.ErrAccessTokenExpired,
		},
		{
			name:          "invalid access token",
			accessToken:   "invalid-access-token",
			mockError:     authErrors.ErrInvalidAccessToken,
			expectedError: authErrors.ErrInvalidAccessToken,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAccessToken := mocks.NewMockAccessToken(ctrl)
			tokenService := New(mockAccessToken, log.NewPlugLogger())

			var parseResult *results.Parse
			if test.mockError == nil {
				parseResult = &results.Parse{
					UserID:    2,
					Roles:     []string{entities.RoleAdmin},
					ExpiresAt: time.Now().Add(time.Minute),
				}
			}

			mockAccessToken.EXPECT().Parse(gomock.Any()).
				Return(parseResult, test.mockError)

			result, err := tokenService.ValidateToken(context.Background(), commands.Validate{
				AccessToken: test.accessToken,
			})

			require.Equal(t, test.expectedError, err)
			if test.expectedError == nil {
				require.Equal(t, parseResult.UserID, result.UserID)
				require.Equal(t, parseResult.Roles, result.Roles)
				require.Equal(t, parseResult.ExpiresAt, result.ExpiresAt)
			}
		})
	}
}
