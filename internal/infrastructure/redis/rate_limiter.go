package redis

import (
	"auth-service/internal/config"
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
)

const prefix = "rate:login:"

type RateLimiter struct {
	client *redis.Client
	cfg    config.RateLimiterConfig
}

func NewRateLimiter(client *redis.Client, cfg config.RateLimiterConfig) *RateLimiter {
	return &RateLimiter{client: client, cfg: cfg}
}

func (rl *RateLimiter) Allow(ctx context.Context, login string) (bool, error) {
	const fn = "infrastructure.redis.RateLimiter.Allow"

	key := prefix + login

	count, err := rl.client.Incr(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("%s: failed to incr key: %w", fn, err)
	}

	if count == 1 {
		rl.client.Expire(ctx, key, rl.cfg.Window)
	}

	if int(count) > rl.cfg.MaxAttempts {
		rl.client.Expire(ctx, key, rl.cfg.BlockDuration)
		return false, nil
	}

	return true, nil
}

func (rl *RateLimiter) Reset(ctx context.Context, login string) error {
	const fn = "infrastructure.redis.RateLimiter.Reset"
	key := prefix + login

	if err := rl.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("%s: failed to del key: %w", fn, err)
	}

	return nil
}
