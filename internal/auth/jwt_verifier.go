package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

var jwksURL = "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs"

var cachedJWKS jwk.Set
var lastFetch time.Time
var cacheDuration = 10 * time.Minute

func VerifyJWT(tokenString string) (bool, error) {
	if time.Since(lastFetch) > cacheDuration || cachedJWKS == nil {
		var err error
		cachedJWKS, err = jwk.Fetch(r.Context(), jwksURL)
		if err != nil {
			return false, fmt.Errorf("failed to fetch JWKS: %w", err)
		}
		lastFetch = time.Now()
	}

	// Parse with validation
	keyfunc := func(t *jwt.Token) (interface{}, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.New("JWT header missing 'kid'")
		}
		key, found := cachedJWKS.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("unable to find key for kid: %s", kid)
		}
		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("failed to get raw key: %w", err)
		}
		return rawKey, nil
	}

	parsedToken, err := jwt.Parse(tokenString, keyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return false, err
	}

	if !parsedToken.Valid {
		return false, errors.New("invalid token")
	}

	return true, nil
}
