package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

var (
	// *** changed: read from environment variable with fallback ***
	jwksURL = func() string {
		if url := os.Getenv("JWKS_URL"); url != "" {
			return url
		}
		return "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs"
	}()

	jwksCache     jwk.Set
	jwksLastFetch time.Time
	// *** changed: TTL is now configurable ***
	jwksTTL = func() time.Duration {
		if val := os.Getenv("JWKS_TTL_MINUTES"); val != "" {
			if ttl, err := time.ParseDuration(val + "m"); err == nil {
				return ttl
			}
		}
		return 10 * time.Minute
	}()

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

	jwksMutex.Lock() // only one writer
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
func VerifyJWT(ctx context.Context, tokenString string) (bool, error) {
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
		key, found := set.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("key with kid %q not found in JWKS", kid)
		}
		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("unable to get raw key: %w", err)
		}
		return rawKey, nil
	}

	expectedIssuer := os.Getenv("JWT_EXPECTED_ISSUER")
	expectedAudience := os.Getenv("JWT_EXPECTED_AUDIENCE")
	validAlgorithms := strings.Split(os.Getenv("JWT_VALID_ALGORITHMS"), ",")

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

	return true, nil
}
