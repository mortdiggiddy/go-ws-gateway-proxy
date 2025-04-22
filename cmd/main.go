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
	"sync"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/auth"
	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/protocol"
	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/proxy"
	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus metrics
var (
	totalConnections = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ws_connections_total",
		Help: "Total number of WebSocket connections",
	})

	protocolConnections = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "ws_protocol_connections_total",
            Help: "Total number of WebSocket connections by protocol",
        }, []string{"protocol"},
    )

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

	proxyErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "ws_proxy_errors_total",
            Help: "Total number of proxy errors by protocol",
        }, []string{"protocol"},
    )

    connectionDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "ws_connection_duration_seconds",
        Help:    "Duration of WebSocket sessions in seconds",
        Buckets: prometheus.DefBuckets,
    })
)

var (
    // WaitGroup to track active WebSocket sessions for graceful draining
    sessionsWg sync.WaitGroup
)

func init() {
	prometheus.MustRegister(totalConnections)
	prometheus.MustRegister(protocolConnections)
	prometheus.MustRegister(authFailures)
	prometheus.MustRegister(authSuccess)
	prometheus.MustRegister(activeSessions)
	prometheus.MustRegister(proxyErrors)
	prometheus.MustRegister(connectionDuration)
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")

		// No origin (e.g. non-browser) is allowed
		if origin == "" {
		    return true
		}

		// Load allowed origins (comma-separated), default to exact if unset
		// can now be set to multiple origins (e.g. https://app1.example.com,https://app2.example.com) 
		// or wildcard suffixes like *.example.com
		allowed := strings.Split(utils.GetEnv("WS_ALLOWED_ORIGINS", origin), ",")

		for _, a := range allowed {
			a = strings.TrimSpace(a)
			// support wildcard suffix like *.ci.dfl.ae
			if strings.HasPrefix(a, "*.") {
				if strings.HasSuffix(origin, a[1:]) {
					return true
				}
			} else if origin == a {
				return true
			}
		}
		return false
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

	// --- Graceful shutdown sequence ---
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutdown initiated, stopping new connections...")

	// Stop accepting new HTTP/WebSocket connections
    ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    server.Shutdown(ctxShutdown) // stops listener but waits for handlers

	// Drain existing sessions
    drainSec := utils.GetEnvInt("GRACEFUL_DRAIN_TIMEOUT_SECONDS", 30)

    log.Printf("Draining active sessions (up to %d seconds)...", drainSec)
    done := make(chan struct{})
    
	go func() {
        sessionsWg.Wait() // wait for all sessions to finish
        close(done)
    }()

	select {
    case <-done:
        log.Println("All sessions drained")
    case <-time.After(time.Duration(drainSec) * time.Second):
        log.Println("Drain timeout reached, exiting")
    }

	log.Println("Shutdown complete")
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	sessionsWg.Add(1)
	defer sessionsWg.Done()

	start := time.Now()
    defer func() {
        connectionDuration.Observe(time.Since(start).Seconds())
    }()

	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}
	defer conn.Close()

	totalConnections.Inc()
	protocolConnections.WithLabelValues(r.URL.Path /* placeholder, replaced later */).Inc() // update label when protocol known

	activeSessions.Inc()
	defer activeSessions.Dec()

	// Read initial CONNECT packet
	_, packet, err := conn.ReadMessage()
	if err != nil {
		log.Println("Failed to read CONNECT packet:", err)
		return
	}

	// Parse CONNECT to extract username and JWT, username optional
	proto, username, jwtToken, err := protocol.ParseConnect(packet, r)

	// If no JWT from CONNECT, try HTTP-only cookie
	if jwtToken == "" {
		// Cookies are sent automatically by the browser if—and only if—
		// 1. the cookie is valid for the target domain (e.g. Domain=.example.com, Secure, HttpOnly, SameSite=None)
		// 2. the server’s CORS response for the WebSocket upgrade includes:
		//       Access‑Control‑Allow‑Origin: https://your-frontend.example.com
		//       Access‑Control‑Allow‑Credentials: true
		// 3. Ensure your session-cookie is set with:
		//       Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=None

		// Example MQTT.js client connection from a front-end application:
		// const client = mqtt.connect({
		//    protocol: 'wss',
		//    hostname: 'my-go-websocket-proxy-public.example.com',
		//    path: '/ws',
		//    wsOptions: { /* this is Node-only */ }
		// });

		// The browser will automatically include your HTTP‑only cookie in the upgrade.
		
		// At the L4/L7 layer (i.e. Traefik) make sure to pass the original X-Forwarded-Proto
		// and X-Forwarded-For headers so that the Golang code can reconstruct the real client IP
		// if you ever need to log or rate limit by IP address

		cookieName := utils.GetEnv("JWT_COOKIE_NAME", "session")
		if c, err := r.Cookie(cookieName); err == nil {
			jwtToken = c.Value
			log.Printf("[auth] extracted JWT from cookie %q", cookieName)
		}
	}

	controlTimeout := time.Duration(utils.GetEnvInt("WS_CONTROL_TIMEOUT_SECONDS", 1)) * time.Second
	
	if err != nil {
		log.Println("CONNECT parse error:", err)
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		conn.WriteControl(
			websocket.CloseMessage, 
			websocket.FormatCloseMessage(1002, "Bad CONNECT"), 
			time.Now().Add(controlTimeout))
		return
	}

	protocolConnections.WithLabelValues(proto).Inc()

	// Decode JWT claims before validation
	claims := jwt.MapClaims{}
	parts := strings.Split(jwtToken, ".")

	if len(parts) != 3 {
		log.Println("Invalid JWT format")
		authFailures.Inc()
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(1008, "Malformed JWT"),
			time.Now().Add(controlTimeout),
		)
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])

	if err != nil {
		log.Println("Failed to decode JWT claims")
		authFailures.Inc()
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(1008, "Malformed JWT payload"),
			time.Now().Add(controlTimeout),
		)
		return
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		log.Println("Failed to parse JWT claims")
		authFailures.Inc()
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(1008, "Invalid JWT claims"),
			time.Now().Add(controlTimeout),
		)
		return
	}

	sub := utils.GetClaim(claims, "sub")
	preferred := utils.GetClaim(claims, "preferred_username")

	if username != "" {
		log.Printf("Accepted %s connection: sub=%s preferred_username=%s", proto, sub, username)
	} else {
		log.Printf("Accepted %s connection: sub=%s preferred_username=%s", proto, sub, preferred)
	}

	// Verify JWT using request context
	valid, err := auth.VerifyJWT(r.Context(), jwtToken, claims)
	if err != nil || !valid {
		log.Printf("JWT invalid: %v\n", err)
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(1008, "JWT invalid or expired"),
			time.Now().Add(controlTimeout),
		)
		return
	}

	authSuccess.WithLabelValues(sub, preferred).Inc()

	var roles []string

    if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
        if rList, ok := realmAccess["roles"].([]interface{}); ok {
            for _, rr := range rList {
                if rs, ok := rr.(string); ok {
                    roles = append(roles, rs)
                }
            }
        }
    }

    if resAcc, ok := claims["resource_access"].(map[string]interface{}); ok {
        for _, v := range resAcc {
            if clientMap, ok := v.(map[string]interface{}); ok {
                if rList, ok := clientMap["roles"].([]interface{}); ok {
                    for _, rr := range rList {
                        if rs, ok := rr.(string); ok {
                            roles = append(roles, rs)
                        }
                    }
                }
            }
        }
    }

	// Proxy traffic to backend
	if err := proxy.ProxyWebSocket(conn, packet, r, proto, jwtToken, roles); err != nil {
		proxyErrors.WithLabelValues(proto).Inc()
		log.Println("Proxying failed:", err)
	}
}

// TODO

// Rate‑limiting / QoS per client or per IP to prevent abuse.

// Circuit breakers or health checks on the upstream RabbitMQ broker so you can fail fast if it’s unavailable.

// Tracing integration (OpenTelemetry) to follow a message from client through the proxy and into the broker.

// Role‑based access controls, if you ever need to differentiate which topics a user can subscribe/publish to.

// Auto‑reconnect logic on the upstream side for transient outages (right now you bail out on any dial error).