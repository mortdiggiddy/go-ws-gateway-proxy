package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

var (
	jwksURL        = "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs"
	jwksCache      jwk.Set
	jwksLastFetch  time.Time
	jwksTTL        = 10 * time.Minute
	jwksMutex      sync.RWMutex
)

// getJWKS fetches and caches the JWKS set with expiration logic
func getJWKS(ctx context.Context) (jwk.Set, error) {
	jwksMutex.RLock()
	if time.Since(jwksLastFetch) < jwksTTL && jwksCache != nil {
		defer jwksMutex.RUnlock()
		return jwksCache, nil
	}
	jwksMutex.RUnlock()

	jwksMutex.Lock()
	defer jwksMutex.Unlock()

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
	log.Println("JWKS refreshed from Keycloak")
	return set, nil
}

// VerifyJWT validates the JWT's signature and expiration using the cached JWKS
func VerifyJWT(ctx context.Context, tokenString string) (bool, error) {
	set, err := getJWKS(ctx)
	if err != nil {
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

	parsedToken, err := jwt.Parse(tokenString, keyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return false, err
	}
	if !parsedToken.Valid {
		return false, errors.New("JWT token is invalid")
	}

	return true, nil
}
