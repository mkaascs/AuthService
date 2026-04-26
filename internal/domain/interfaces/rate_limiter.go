package interfaces

import "context"

type RateLimiter interface {
	Allow(ctx context.Context, login string) (bool, error)
	Reset(ctx context.Context, login string) error
}
