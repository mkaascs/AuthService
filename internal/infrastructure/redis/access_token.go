package redis

import (
	"auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/interfaces/repositories"
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
)

type AccessTokenRepo struct {
	client *redis.Client
}

func NewAccessTokenRepo(client *redis.Client) repositories.AccessTokenRepo {
	return &AccessTokenRepo{client: client}
}

func (atr *AccessTokenRepo) Revoke(ctx context.Context, command commands.Revoke) error {
	const fn = "infrastructure.redis.AccessTokenRepo.Revoke"

	key := fmt.Sprintf("blacklist:%s", command.JTI)
	if err := atr.client.Set(ctx, key, 1, command.TTL).Err(); err != nil {
		return fmt.Errorf("%s: failed to revoke token: %w", fn, err)
	}

	return nil
}

func (atr *AccessTokenRepo) IsRevoked(ctx context.Context, jti string) (bool, error) {
	const fn = "infrastructure.redis.AccessTokenRepo.IsRevoked"

	key := fmt.Sprintf("blacklist:%s", jti)
	exists, err := atr.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("%s: failed to check if revoked token exists: %w", fn, err)
	}

	return exists == 1, nil
}
