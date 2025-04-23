package auth

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	_ "github.com/lib/pq"
	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/utils"
)

var (
	cacheStore  = strings.ToLower(getEnv("JWT_CACHE_STORE", "memory"))
	cachePrefix = getEnv("JWT_CACHE_PREFIX", "jwt_cached_token_")
)

type TokenCache interface {
	Get(ctx context.Context, key string) (bool, error)
	Set(ctx context.Context, key string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

var (
	tokenCache TokenCache
	onceCache  sync.Once
)

// initTokenCache initializes the chosen cache backend
func initTokenCache() {
	onceCache.Do(func() {
		switch cacheStore {
		case "redis":
			url := utils.GetEnv("REDIS_URL")
			if url == "" {
				log.Println("REDIS_URL not set; falling back to memory cache")
				tokenCache = newMemoryCache()
				return
			}
			_, err := redis.ParseURL(url)
			if err != nil {
				log.Printf("invalid REDIS_URL: %v; falling back to memory cache", err)
				tokenCache = newMemoryCache()
				return
			}
			client := utils.GetRedisClient()
			tokenCache = &redisCache{client: client}

		case "postgres":
			dsn := utils.GetEnv("POSTGRES_DSN")
			if dsn == "" {
				log.Println("POSTGRES_DSN not set; falling back to memory cache")
				tokenCache = newMemoryCache()
				return
			}
			db, err := sql.Open("postgres", dsn)
			if err != nil {
				log.Printf("failed to connect postgres: %v; falling back to memory cache", err)
				tokenCache = newMemoryCache()
				return
			}
			// ensure cache table exists
			_, err = db.Exec(`CREATE TABLE IF NOT EXISTS jwt_cache (key TEXT PRIMARY KEY, expires TIMESTAMPTZ)`)
			if err != nil {
				log.Printf("failed to create cache table: %v; falling back to memory cache", err)
				tokenCache = newMemoryCache()
				return
			}
			tokenCache = &postgresCache{db: db}

		default:
			tokenCache = newMemoryCache()
		}
	})
}

// Returns the singleton initialized cache.
func GetTokenCache() TokenCache {
	initTokenCache()
	return tokenCache
}

// memoryCache is a simple in-memory TTL map
type memoryCache struct {
	mu    sync.RWMutex
	items map[string]time.Time
}

func newMemoryCache() TokenCache {
	return &memoryCache{items: make(map[string]time.Time)}
}

func (m *memoryCache) Get(ctx context.Context, key string) (bool, error) {
	realKey := cachePrefix + key
	m.mu.RLock()
	exp, ok := m.items[realKey]
	m.mu.RUnlock()
	if !ok {
		return false, nil
	}
	if time.Now().After(exp) {
		m.mu.Lock()
		delete(m.items, realKey)
		m.mu.Unlock()
		return false, nil
	}
	return true, nil
}

func (m *memoryCache) Set(ctx context.Context, key string, ttl time.Duration) error {
	realKey := cachePrefix + key
	m.mu.Lock()
	m.items[realKey] = time.Now().Add(ttl)
	m.mu.Unlock()
	return nil
}

func (m *memoryCache) Delete(ctx context.Context, key string) error {
	realKey := cachePrefix + key
	m.mu.Lock()
	delete(m.items, realKey)
	m.mu.Unlock()
	return nil
}

// redisCache uses Redis SET with TTL and EXISTS
type redisCache struct{ client *redis.Client }

func (r *redisCache) Get(ctx context.Context, key string) (bool, error) {
	realKey := cachePrefix + key
	exists, err := r.client.Exists(ctx, realKey).Result()
	return exists == 1, err
}

func (r *redisCache) Set(ctx context.Context, key string, ttl time.Duration) error {
	realKey := cachePrefix + key
	return r.client.Set(ctx, realKey, "1", ttl).Err()
}

func (r *redisCache) Delete(ctx context.Context, key string) error {
	realKey := cachePrefix + key
	return r.client.Del(ctx, realKey).Err()
}

// postgresCache stores expiration timestamps in a Postgres table
type postgresCache struct{ db *sql.DB }

// TODO(postgresCache): Expired key cleanup strategy
//
// Currently, expired JWT cache entries in Postgres are only removed during `Get()` calls.
// This lazy deletion strategy can lead to unbounded table growth in high-throughput environments.
//
// ✅ Works correctly per access, avoids expired reuse
// ❌ Expired keys remain until manually accessed
//
// Possible solutions:
// - [ ] Schedule periodic cleanup: `DELETE FROM jwt_cache WHERE expires < now()`
// - [ ] Add index on expires: `CREATE INDEX idx_jwt_cache_expires ON jwt_cache (expires);`
// - [ ] Use pg_cron or external job scheduler for TTL purging
// - [ ] Consider switching to Redis for native TTL support in volatile cache environments
func (p *postgresCache) Get(ctx context.Context, key string) (bool, error) {
	realKey := cachePrefix + key
	var exp time.Time
	err := p.db.QueryRowContext(ctx, "SELECT expires FROM jwt_cache WHERE key=$1", realKey).Scan(&exp)
	if err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if time.Now().After(exp) {
		p.db.ExecContext(ctx, "DELETE FROM jwt_cache WHERE key=$1", realKey)
		return false, nil
	}
	return true, nil
}

func (p *postgresCache) Set(ctx context.Context, key string, ttl time.Duration) error {
	realKey := cachePrefix + key
	exp := time.Now().Add(ttl)
	// upsert expiration correctly
	_, err := p.db.ExecContext(ctx, `
           INSERT INTO jwt_cache (key, expires) VALUES ($1, $2)
           ON CONFLICT (key) DO UPDATE SET expires = EXCLUDED.expires
       `, realKey, exp)
	return err
}

func (p *postgresCache) Delete(ctx context.Context, key string) error {
	realKey := cachePrefix + key
	_, err := p.db.ExecContext(ctx, "DELETE FROM jwt_cache WHERE key = $1", realKey)
	return err
}

// helper to read env vars
func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
