package auth

import (
	"auth-service/internal/delivery/grpc/util"
	"auth-service/internal/domain/dto/tokens/commands"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/domain/interfaces/services"
	"context"
	"errors"
	authv1 "github.com/mkaascs/AuthProto/gen/go/auth"
	"google.golang.org/grpc"
)

type tokenServer struct {
	authv1.UnimplementedTokenServer
	tokens services.Token
}

func (ts *tokenServer) ValidateToken(ctx context.Context, request *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	// TODO: validate

	result, err := ts.tokens.ValidateToken(ctx, commands.Validate{
		AccessToken: request.AccessToken,
	})

	if err != nil {
		if errors.Is(err, authErrors.ErrInvalidAccessToken) {
			return &authv1.ValidateTokenResponse{
				Status: authv1.TokenStatus_INVALID,
			}, nil
		}

		if errors.Is(err, authErrors.ErrAccessTokenExpired) {
			return &authv1.ValidateTokenResponse{
				Status: authv1.TokenStatus_EXPIRED,
			}, nil
		}

		if errors.Is(err, authErrors.ErrAccessTokenRevoked) {
			return &authv1.ValidateTokenResponse{
				Status: authv1.TokenStatus_REVOKED,
			}, nil
		}

		return nil, util.MapError(err)
	}

	return &authv1.ValidateTokenResponse{
		Status:    authv1.TokenStatus_VALID,
		UserId:    result.UserID,
		Roles:     result.Roles,
		ExpiresAt: result.ExpiresAt.Unix(),
	}, nil
}

func RegisterTokenServer(gRPC *grpc.Server, tokens services.Token) {
	authv1.RegisterTokenServer(gRPC, &tokenServer{tokens: tokens})
}
