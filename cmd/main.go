package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/auth"
	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/mqtt"
	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/proxy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus metrics
var (
	totalConnections = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ws_total_connections",
		Help: "Total number of WebSocket connections",
	})

	authFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ws_auth_failures_total",
		Help: "Total number of failed JWT authentications",
	})

	authSuccess = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ws_auth_success_total",
		Help: "Total number of successful JWT authentications",
	}, []string{"sub", "preferred_username"})

	activeSessions = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ws_active_sessions",
		Help: "Currently active proxied WebSocket sessions",
	})
)

func init() {
	prometheus.MustRegister(totalConnections)
	prometheus.MustRegister(authFailures)
	prometheus.MustRegister(authSuccess)
	prometheus.MustRegister(activeSessions)
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Production-safe origin check
		origin := r.Header.Get("Origin")
		return origin == "https://your-frontend.com" || origin == ""
	},
}

func main() {
	http.HandleFunc("/ws", handleWebSocket)

	// healthz for K8s liveness/readiness probes
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr: ":8080",
	}

	go func() {
		log.Println("Listening on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown support
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}
	defer conn.Close()

	totalConnections.Inc()
	activeSessions.Inc()
	defer activeSessions.Dec()

	// Step 1: Read initial CONNECT packet
	_, packet, err := conn.ReadMessage()
	if err != nil {
		log.Println("Failed to read CONNECT packet:", err)
		return
	}

	// Parse CONNECT to extract username and JWT, username optional
	protocol, username, jwtToken, err := mqtt.ParseConnect(packet)
	if err != nil {
		log.Println("CONNECT parse error:", err)
		conn.WriteControl(
			websocket.CloseMessage, 
			websocket.FormatCloseMessage(1002, "Bad CONNECT"), 
			time.Now().Add(1*time.Second))
		return
	}

	if protocol == "raw" {
		log.Println("Raw WebSocket connection detected. Forwarding to upstream raw WS backend.") // *** comment
		if err := proxy.ProxyWebSocket(conn, packet, r); err != nil {
			log.Println("Proxying raw WS failed:", err)
		}
		return
	}

	// Decode JWT claims before validation
	claims := jwt.MapClaims{}
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		log.Println("Invalid JWT format")
		authFailures.Inc()
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(1008, "Malformed JWT"),
			time.Now().Add(1*time.Second),
		)
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Println("Failed to decode JWT claims")
		authFailures.Inc()
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(1008, "Malformed JWT payload"),
			time.Now().Add(1*time.Second),
		)
		return
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		log.Println("Failed to parse JWT claims")
		authFailures.Inc()
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(1008, "Invalid JWT claims"),
			time.Now().Add(1*time.Second),
		)
		return
	}

	sub := getClaim(claims, "sub")
	preferred := getClaim(claims, "preferred_username")

	if username != "" {
		log.Printf("CONNECT from user=%s\n", username)
	} else {
		log.Printf("CONNECT from preferred_username=%s\n", preferred)
	}

	// Verify JWT using request context
	valid, err := auth.VerifyJWT(r.Context(), jwtToken)
	if err != nil || !valid {
		log.Printf("JWT invalid: %v\n", err) 
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(1008, "JWT invalid or expired"),
			time.Now().Add(1*time.Second),
		)
		return
	}

	authSuccess.WithLabelValues(sub, preferred).Inc()

	// Proxy traffic to backend
	if err := proxy.ProxyWebSocket(conn, packet, r); err != nil {
		log.Println("Proxying failed:", err)
	}
}

func getClaim(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return "unknown"
}
