package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/auth"
	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/utils"
)

type revokeRequest struct {
	Sub string `json:"sub"`
	JTI string `json:"jti"`
}

// Accepts POST /admin/revoke with JSON { "sub": "...", "jti": "..." }
// It evicts the token from the cache and broadcasts a revocation via Redis.
func RevokeHandler(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Sub == "" {
		http.Error(w, "missing required field: sub", http.StatusBadRequest)
		return
	}
	if req.JTI == "" {
		http.Error(w, "missing required field: jti", http.StatusBadRequest)
		return
	}

	// Build the cache key
	key := fmt.Sprintf("%s:%s", req.Sub, req.JTI)

	// Evict from token cache
	if err := auth.GetTokenCache().Delete(context.Background(), key); err != nil {
		http.Error(w, "cache eviction failed", http.StatusInternalServerError)
		return
	}

	// Publish revocation “poison pill” to all proxy pods
	channel := "ws:revocations:" + key
	if err := utils.GetRedisClient().
		Publish(context.Background(), channel, "1").
		Err(); err != nil {
		http.Error(w, "failed to publish revocation", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
