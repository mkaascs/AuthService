package services

import (
	"auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/entities"
	authErrors "auth-service/internal/domain/entities/errors"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type AccessTokenTestSuite struct {
	New     func(t *testing.T, tokenTTL time.Duration) AccessToken
	Cleanup func(t *testing.T)
}

func (ts *AccessTokenTestSuite) RunGenerateTests(t *testing.T) {
	tests := []struct {
		name   string
		userId int64
		roles  []string
	}{
		{
			name:   "generate for user role",
			userId: 1,
			roles:  []string{entities.RoleUser},
		},
		{
			name:   "generate for admin role",
			userId: 2,
			roles:  []string{entities.RoleAdmin, entities.RoleUser},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := ts.New(t, 15*time.Minute)
			if ts.Cleanup != nil {
				defer ts.Cleanup(t)
			}

			result, err := service.Generate(commands.Generate{
				UserID: test.userId,
				Roles:  test.roles,
			})

			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotEmpty(t, result.Token)

			parsed, err := service.Parse(commands.Parse{
				Token: result.Token,
			})

			require.NoError(t, err)
			require.NotNil(t, parsed)
			require.Equal(t, test.userId, parsed.UserID)
			require.Equal(t, test.roles, parsed.Roles)
		})
	}
}

func (ts *AccessTokenTestSuite) RunParseTests(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		generateToken bool
		userId        int64
		roles         []string
		tokenTTL      time.Duration
		expectedErr   error
		anyErr        bool
	}{
		{
			name:          "parse access token successfully",
			generateToken: true,
			userId:        1,
			roles:         []string{entities.RoleUser},
			tokenTTL:      15 * time.Minute,
			expectedErr:   nil,
			anyErr:        false,
		},
		{
			name:          "parse expired access token",
			generateToken: true,
			userId:        1,
			roles:         []string{entities.RoleAdmin, entities.RoleUser},
			tokenTTL:      time.Nanosecond,
			expectedErr:   authErrors.ErrAccessTokenExpired,
			anyErr:        false,
		},
		{
			name:          "parse incomplete access token",
			generateToken: false,
			tokenTTL:      15 * time.Minute,
			token:         "header.payload",
			expectedErr:   authErrors.ErrInvalidAccessToken,
			anyErr:        false,
		},
		{
			name:          "parse invalid access token",
			generateToken: false,
			tokenTTL:      15 * time.Minute,
			token:         "",
			expectedErr:   authErrors.ErrInvalidAccessToken,
			anyErr:        false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := ts.New(t, test.tokenTTL)
			if ts.Cleanup != nil {
				defer ts.Cleanup(t)
			}

			if test.generateToken {
				result, err := service.Generate(commands.Generate{
					UserID: test.userId,
					Roles:  test.roles,
				})

				require.NoError(t, err)
				require.NotNil(t, result)
				require.NotEmpty(t, result.Token)

				test.token = result.Token
			}

			result, err := service.Parse(commands.Parse{
				Token: test.token,
			})

			if test.anyErr {
				require.Error(t, err)
				require.Nil(t, result)
				return
			}

			if test.expectedErr != nil {
				require.ErrorIs(t, err, test.expectedErr)
				require.Nil(t, result)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, test.userId, result.UserID)
			require.Equal(t, test.roles, result.Roles)
		})
	}
}
