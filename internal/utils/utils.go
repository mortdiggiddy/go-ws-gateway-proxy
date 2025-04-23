package utils

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
)

var (
	redisOnce sync.Once
	redisCli  *redis.Client
)

func GetRedisClient() *redis.Client {
	redisOnce.Do(func() {
		opt, err := redis.ParseURL(GetEnv("REDIS_URL", ""))
		if err != nil {
			panic("invalid REDIS_URL: " + err.Error())
		}
		redisCli = redis.NewClient(opt)
	})
	return redisCli
}

// GetEnv returns the value of the environment variable or a default (empty string if no default supplied)
func GetEnv(key string, def ...string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	if len(def) > 0 {
		return def[0]
	}
	return ""
}

// Reads an integer environment variable or returns a default
func GetEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

// Retrieves a string claim from jwt.MapClaims or returns "unknown"
func GetClaim(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return "unknown"
}

// extractCacheKey builds a cache key combining sub and jti when available, reusing pre-unmarshaled claims
func ExtractCacheKeyFromClaims(claims jwt.MapClaims) (string, error) {
	sub := GetClaim(claims, "sub")
	jti := GetClaim(claims, "jti")

	// combine sub and jti
	if sub != "" && jti != "" {
		return fmt.Sprintf("%s:%s", sub, jti), nil
	}

	if jti != "" {
		return jti, nil // fallback to jti alone
	}

	if sub != "" {
		return sub, nil // fallback to sub alone
	}

	return "", fmt.Errorf("no sub or jti claim")
}

// Reads a time.Duration from env (e.g. "5s", "1m") or returns def
func GetEnvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
