package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"golang.org/x/time/rate"
)

// Defines the interface for rate limiting checks.
type RateLimiter interface {
	// Allow returns true if the action for the given key is permitted.
	Allow(key string) bool
}

// Uses Go's in-memory token bucket.
type LocalRateLimiter struct {
	limiter *rate.Limiter
}

// Constructs a LocalRateLimiter allowing perSecond events and burst.
func NewLocalRateLimiter(perSecond, burst int) *LocalRateLimiter {
	return &LocalRateLimiter{
		limiter: rate.NewLimiter(rate.Limit(perSecond), burst),
	}
}

// Allow checks if the local limiter permits another event.
func (l *LocalRateLimiter) Allow(_ string) bool {
	return l.limiter.Allow()
}

// Coordinates rate limits across instances via Redis.
type RedisRateLimiter struct {
	client *redis.Client
	burst  int
	prefix string
	window time.Duration
}

// Constructs a RedisRateLimiter.
// prefix namespaces the Redis keys.
func NewRedisRateLimiter(client *redis.Client, burst int, prefix string) *RedisRateLimiter {
	return &RedisRateLimiter{
		client: client,
		burst:  burst,
		prefix: prefix,
		window: time.Second,
	}
}

func (r *RedisRateLimiter) WithWindow(d time.Duration) *RedisRateLimiter {
	r.window = d
	return r
}

// Allow uses a 1-second fixed window in Redis. Returns false if count > burst.
func (r *RedisRateLimiter) Allow(key string) bool {
	now := time.Now().Unix()
	redisKey := fmt.Sprintf("%s:%s:%d", r.prefix, key, now)
	ctx := context.Background()

	// atomic Lua script, 1 network round trip
	// Set-once logic (e.g., SETNX + EXPIRE)
	// If it's the first increment, the expiration is always set
	// You don’t rely on client-side condition checks which might become stale under load
	// Fixed-window counters
	// Distributed locks
	script := redis.NewScript(`
		local current
		current = redis.call("INCR", KEYS[1])
		if tonumber(current) == 1 then
			redis.call("EXPIRE", KEYS[1], ARGV[1])
		end
		return current
	`)

	result, err := script.Run(ctx, r.client, []string{redisKey}, int(r.window.Seconds())).Result()
	if err != nil {
		// Fail open if Redis unavailable
		return true
	}

	count, ok := result.(int64)
	if !ok {
		return true // defensive fallback
	}

	return int(count) <= r.burst
}
