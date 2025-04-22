package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/utils"
)

var (
	// *** changed: read from environment variable with fallback ***
	jwksURL = utils.GetEnv(
		"JWKS_URL",
		"https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs",
	)

	jwksCache     jwk.Set
	jwksLastFetch time.Time
	// *** changed: TTL is now configurable ***
	jwksTTL = time.Duration(utils.GetEnvInt("JWKS_TTL_MINUTES", 10)) * time.Minute

	jwksMutex sync.RWMutex
)

// getJWKS fetches and caches the JWKS set with expiration logic
func getJWKS(ctx context.Context) (jwk.Set, error) {
	jwksMutex.RLock() // multiple readers for RLock, optimistic read

	if time.Since(jwksLastFetch) < jwksTTL && jwksCache != nil {
		defer jwksMutex.RUnlock()
		return jwksCache, nil
	}

	jwksMutex.RUnlock()

	jwksMutex.Lock()         // only one writer
	defer jwksMutex.Unlock() // always release

	// Double-check after acquiring write lock
	if time.Since(jwksLastFetch) < jwksTTL && jwksCache != nil {
		return jwksCache, nil
	}

	set, err := jwk.Fetch(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	jwksCache = set
	jwksLastFetch = time.Now()
	log.Println("JWKS refreshed.")
	return set, nil
}

// VerifyJWT validates the JWT's signature, claims, and expiration using the cached JWKS
func VerifyJWT(ctx context.Context, tokenString string, claims jwt.MapClaims) (bool, error) {
	initTokenCache()

	key, keyErr := extractCacheKeyFromClaims(claims)

	if keyErr == nil {
		if found, err := tokenCache.Get(ctx, key); err == nil && found {
			return true, nil // cached valid token
		}
	}

	set, err := getJWKS(ctx)
	if err != nil {
		log.Printf("error retrieving JWKS: %v", err)
		return false, err
	}

	keyfunc := func(t *jwt.Token) (interface{}, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.New("JWT header missing 'kid'")
		}
		jwkKey, found := set.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("key with kid %q not found in JWKS", kid)
		}
		var rawKey interface{}
		if err := jwkKey.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("unable to get raw key: %w", err)
		}
		return rawKey, nil
	}

	expectedIssuer := utils.GetEnv("JWT_EXPECTED_ISSUER", "")
	expectedAudience := utils.GetEnv("JWT_EXPECTED_AUDIENCE", "")
	validAlgorithms := strings.Split(utils.GetEnv("JWT_VALID_ALGORITHMS", ""), ",")

	if len(validAlgorithms) == 0 || validAlgorithms[0] == "" {
		validAlgorithms = []string{"RS256"} // default
	}

	for i := range validAlgorithms {
		validAlgorithms[i] = strings.TrimSpace(validAlgorithms[i])
	}

	opts := []jwt.ParserOption{
		jwt.WithValidMethods(validAlgorithms),
		jwt.WithIssuer(expectedIssuer),
	}
	for _, aud := range strings.Split(expectedAudience, ",") {
		opts = append(opts, jwt.WithAudience(strings.TrimSpace(aud)))
	}

	parsedToken, err := jwt.Parse(tokenString, keyfunc, opts...)

	if err != nil {
		log.Printf("JWT parsing failed: %v", err)
		return false, err
	}

	if !parsedToken.Valid {
		log.Printf("JWT token is invalid")
		return false, errors.New("JWT token is invalid")
	}

	var ttl time.Duration
	if expVal, exists := claims["exp"]; exists {
		switch v := expVal.(type) {
		case float64:
			expTime := time.Unix(int64(v), 0)
			ttl = time.Until(expTime) // staticcheck compliant
		case json.Number:
			if iv, err := v.Int64(); err == nil {
				expTime := time.Unix(iv, 0)
				ttl = time.Until(expTime)
			}
		}
	}

	// fallback TTL if parsing failed or expired
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	tokenCache.Set(ctx, key, ttl) // store in cache

	return true, nil
}

// extractCacheKey builds a cache key combining sub and jti when available, reusing pre-unmarshaled claims
func extractCacheKeyFromClaims(claims jwt.MapClaims) (string, error) {
	sub := utils.GetClaim(claims, "sub")
	jti := utils.GetClaim(claims, "jti")

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
