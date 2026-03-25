package services

import (
	"auth-service/internal/domain/dto/tokens/commands"
	authErrors "auth-service/internal/domain/entities/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type AccessTokenTestSuite struct {
	New     func(t *testing.T, tokenTTL time.Duration) AccessToken
	Cleanup func(t *testing.T)
}

func (ts *AccessTokenTestSuite) RunGenerateTests(t *testing.T) {
	t.Run("generate access token", ts.testGenerate)
}

func (ts *AccessTokenTestSuite) RunParseTests(t *testing.T) {
	t.Run("parse access token", ts.testParse)
	t.Run("parse expired access token", ts.testParseExpired)
	t.Run("parse invalid access token", ts.testParseInvalid)
}

func (ts *AccessTokenTestSuite) testGenerate(t *testing.T) {
	tests := []struct {
		id   int64
		role string
	}{
		{54, "user"},
		{20, "vip"},
		{2, "admin"},
	}

	for _, test := range tests {
		t.Run(test.role, func(t *testing.T) {
			service := ts.New(t, 15*time.Minute)
			if ts.Cleanup != nil {
				defer ts.Cleanup(t)
			}

			result, err := service.Generate(commands.Generate{
				UserID: test.id,
				Role:   test.role,
			})

			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotEmpty(t, result.Token)

			parsed, err := service.Parse(commands.Parse{
				Token: result.Token,
			})

			require.NoError(t, err)
			require.NotNil(t, parsed)
			assert.Equal(t, test.id, parsed.UserID)
			assert.Equal(t, test.role, parsed.Role)
		})
	}
}

func (ts *AccessTokenTestSuite) testParse(t *testing.T) {
	ts.testGenerate(t)
}

func (ts *AccessTokenTestSuite) testParseExpired(t *testing.T) {
	tests := []struct {
		id   int64
		role string
	}{
		{54, "user"},
		{20, "vip"},
		{2, "admin"},
	}

	for _, test := range tests {
		t.Run(test.role, func(t *testing.T) {
			service := ts.New(t, time.Nanosecond)
			if ts.Cleanup != nil {
				defer ts.Cleanup(t)
			}

			result, err := service.Generate(commands.Generate{
				UserID: test.id,
				Role:   test.role,
			})

			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotEmpty(t, result.Token)

			parsed, err := service.Parse(commands.Parse{
				Token: result.Token,
			})

			assert.ErrorIs(t, err, authErrors.ErrAccessTokenExpired)
			assert.Nil(t, parsed)
		})
	}
}

func (ts *AccessTokenTestSuite) testParseInvalid(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"random", "mkaascs"},
		{"incomplete", "header.payload"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := ts.New(t, 15*time.Minute)
			if ts.Cleanup != nil {
				defer ts.Cleanup(t)
			}

			result, err := service.Parse(commands.Parse{
				Token: test.token,
			})

			assert.Nil(t, result)
			assert.Error(t, err)
		})
	}
}
