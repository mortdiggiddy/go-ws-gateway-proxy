package utils

import (
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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

// Reads a time.Duration from env (e.g. "5s", "1m") or returns def
func GetEnvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
