package proxy

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/protocol"
	"github.com/mortdiggiddy/go-ws-gateway-proxy/internal/utils"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"
)

type ctxKey string

const ctxKeyConnID ctxKey = "conn_id"

var (
	// retry attempts per protocol
	proxyRetries = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ws_proxy_retries_total",
			Help: "Total number of upstream reconnect attempts by protocol",
		},
		[]string{"protocol"},
	)
	// circuit opens per protocol
	circuitOpenCount = prometheus.NewCounterVec( // *** made into CounterVec ***
		prometheus.CounterOpts{
			Name: "ws_circuit_open_total",
			Help: "Total number of times circuit breaker opened by protocol",
		},
		[]string{"protocol"}, // ***
	)
	// health check successes and failures
	healthSuccess = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ws_upstream_health_success_total", // ***
			Help: "Total successful upstream health checks",
		},
	)
	healthFail = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ws_upstream_health_failure_total", // ***
			Help: "Total failed upstream health checks",
		},
	)
)

// Circuit breaker state
var (
	cbFailureCount    int
	cbOpenUntil       time.Time
	cbMutex           sync.Mutex
	cbThreshold       = utils.GetEnvInt("CB_FAILURE_THRESHOLD", 5)                                          // failures to open circuit
	cbOpenDuration    = time.Duration(utils.GetEnvInt("CB_OPEN_TIMEOUT_SECONDS", 60)) * time.Second         // open duration
	cbHealthInterval  = time.Duration(utils.GetEnvInt("CB_HEALTHCHECK_INTERVAL_SECONDS", 30)) * time.Second // health check interval
	dialRetryMax      = utils.GetEnvInt("WS_DIAL_RETRY_MAX", 3)                                             // dial retry count
	dialRetryInterval = time.Duration(utils.GetEnvInt("WS_DIAL_RETRY_INTERVAL_SECONDS", 2)) * time.Second   // retry backoff

	upstreamWSURL = utils.GetEnv("UPSTREAM_WS_URL")
	writeTimeout  = time.Duration(utils.GetEnvInt("WS_WRITE_TIMEOUT_SECONDS", 10)) * time.Second
	idleTimeout   = time.Duration(utils.GetEnvInt("WS_IDLE_TIMEOUT_SECONDS", 60)) * time.Second
)

func init() {
	prometheus.MustRegister(proxyRetries, circuitOpenCount, healthSuccess, healthFail)
	go upstreamHealthCheck()
}

// ProxyWebSocket streams traffic between clientConn and an upstream WebSocket server
// This function is the lifetime of a single proxy session between a client and an
// upstream WebSocket. It stays alive as long as both parties are connected and talking
// Works seamlessly with:
// RabbitMQ
// EMQX
// Mosquitto with WebSocket bridge
// Any custom WebSocket target
func ProxyWebSocket(clientConn *websocket.Conn, initial []byte, req *http.Request, proto string, jwtToken string, roles []string) error {
	connID := uuid.NewString()
	ctx := context.WithValue(req.Context(), ctxKeyConnID, connID)

	var clientWriteMu sync.Mutex
	var upstreamReadMu sync.Mutex
	var upstreamWriteMu sync.Mutex

	if isCircuitOpen(proto) {
		log.Printf("[proxy] circuit open for protocol=%s; refusing connection", proto)
		return fmt.Errorf("upstream circuit open, refusing connection")
	}

	limiter := rate.NewLimiter(
		rate.Limit(utils.GetEnvInt("RATE_LIMIT_PER_SECOND", 10)), // messages/sec
		utils.GetEnvInt("RATE_LIMIT_BURST", 20),                  // burst capacity
	)

	// MQTT‑5 Role Injection
	if proto == "mqtt" {
		var err error
		initial, err = protocol.InjectUserProperties(initial, strings.Join(roles, ","))

		if err != nil {
			log.Printf("[proxy] Failed to inject MQTT roles: %v", err)
		}
	}

	u, perr := url.Parse(upstreamWSURL)
	if perr != nil {
		log.Printf("[proxy] invalid upstream URL %q: %v", upstreamWSURL, perr)
		return perr
	}

	// build dial headers for raw WS including Authorization and roles
	hdr := http.Header{}
	if proto == "raw" {
		hdr.Set("Authorization", "Bearer "+jwtToken)
		if len(roles) > 0 {
			hdr.Set("X-User-Roles", strings.Join(roles, ","))
		}
	}

	var upstreamConn *websocket.Conn
	var dialErr error

	// initial dial with retry loop and backoff
	for i := 0; i < dialRetryMax; i++ {
		upstreamConn, _, dialErr = websocket.DefaultDialer.Dial(u.String(), hdr)

		if dialErr != nil {
			proxyRetries.WithLabelValues(proto).Inc() // instrument retries
			log.Printf("[proxy] dial attempt %d/%d failed for protocol=%s: %v", i+1, dialRetryMax, proto, dialErr)
			select {
			case <-ctx.Done(): // abort on shutdown
				return ctx.Err()
			default:
			}
			time.Sleep(dialRetryInterval)
			continue
		}

		resetCircuit(proto) // reset on success
		break
	}
	if dialErr != nil {
		recordFailure(ctx, proto) // count CB open if threshold
		log.Printf("[proxy] failed to dial upstream after %d attempts for protocol=%s: %v", dialRetryMax, proto, dialErr)
		return fmt.Errorf("failed to dial upstream after %d attempts: %w", dialRetryMax, dialErr)
	}

	// cleanup
	var closeOnce sync.Once
	closeFunc := func() {
		clientConn.Close()
		upstreamConn.Close()
	}
	defer closeOnce.Do(closeFunc)

	// Set up Pong handlers to extend read deadlines upon pong
	clientConn.SetPongHandler(func(appData string) error {
		clientConn.SetReadDeadline(time.Now().Add(idleTimeout)) // read deadline refresh
		return nil
	})
	upstreamConn.SetPongHandler(func(appData string) error {
		upstreamConn.SetReadDeadline(time.Now().Add(idleTimeout)) // read deadline refresh
		return nil
	})

	// Forward initial CONNECT packet (for MQTT) or ignore for raw
	upstreamWriteMu.Lock()
	upstreamConn.SetWriteDeadline(time.Now().Add(writeTimeout))
	ierr := upstreamConn.WriteMessage(websocket.BinaryMessage, initial)
	upstreamWriteMu.Unlock()
	if ierr != nil {
		log.Printf("[proxy] failed to send initial packet to upstream: %v", ierr)
		closeOnce.Do(closeFunc)
		return ierr
	}

	pingTicker := time.NewTicker(idleTimeout / 2)

	// Start ping loop
	go func() {
		defer pingTicker.Stop()
		for {
			select {
			case <-ctx.Done(): // abort on shutdown
				return
			case <-pingTicker.C:
				clientWriteMu.Lock()
				clientConn.SetWriteDeadline(time.Now().Add(writeTimeout))
				cerr := clientConn.WriteMessage(websocket.PingMessage, nil)
				clientWriteMu.Unlock()

				if cerr != nil {
					log.Printf("[proxy] client ping failed: %v", cerr)
					closeOnce.Do(closeFunc)
					return
				}

				upstreamWriteMu.Lock()
				upstreamConn.SetWriteDeadline(time.Now().Add(writeTimeout))
				uerr := upstreamConn.WriteMessage(websocket.PingMessage, nil)
				upstreamWriteMu.Unlock()

				if uerr != nil {
					log.Printf("[proxy] upstream ping failed: %v", uerr)
					closeOnce.Do(closeFunc)
					return
				}
			}
		}
	}()

	errChan := make(chan error, 2)

	// Client -> Upstream with mid‑stream reconnect

	// Each frame (text/binary) is read from one socket and directly forwarded to the other, preserving:
	// WebSocket message boundaries
	// MQTT framing and binary structure
	// Native duplex communication
	// Latency:
	// No parsing: Not decoding or modifying payloads
	// No buffering: Data is immediately forwarded as it's read
	// No context switching: Each direction is handled in a simple goroutine
	// No TLS termination overhead (unless used upstream)

	// In practice, you’ll hit OS limits on open file descriptors (tune ulimit -n) and memory
	// pressure if you push beyond tens of thousands of concurrent connections per pod.

	// Once a client upgrades, its TCP connection stays bound to the same pod until closed.
	// You don’t need explicit “session affinity” for an established socket.
	go func() {
		for {

			// rate limit incoming client frames
			if !limiter.Allow() {
				clientWriteMu.Lock()
				clientConn.SetWriteDeadline(time.Now().Add(writeTimeout))
				clientConn.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(1008, "Rate limit exceeded"),
					time.Now().Add(writeTimeout),
				)
				clientWriteMu.Unlock()
				errChan <- fmt.Errorf("rate limit exceeded by client")
				return
			}

			clientConn.SetReadDeadline(time.Now().Add(idleTimeout)) // configurable if needed
			mt, msg, rerr := clientConn.ReadMessage()

			if rerr != nil {
				log.Printf("[proxy] client read error: %v", rerr)
				if tryUpstreamReconnect(ctx, &upstreamConn, hdr, proto, &upstreamReadMu, &upstreamWriteMu) {
					continue
				}
				recordFailure(ctx, proto)
				errChan <- rerr
				return
			}

			upstreamWriteMu.Lock()
			upstreamConn.SetWriteDeadline(time.Now().Add(writeTimeout))
			werr := upstreamConn.WriteMessage(mt, msg)
			upstreamWriteMu.Unlock()

			if werr != nil {
				log.Printf("[proxy] forward to upstream failed: %v", werr)
				if tryUpstreamReconnect(ctx, &upstreamConn, hdr, proto, &upstreamReadMu, &upstreamWriteMu) {
					continue
				}
				recordFailure(ctx, proto)
				errChan <- werr
				return
			}
		}
	}()

	// Upstream -> Client with same mid‑stream reconnect

	go func() {
		for {
			upstreamReadMu.Lock()
			upstreamConn.SetReadDeadline(time.Now().Add(idleTimeout))
			mt, msg, rerr := upstreamConn.ReadMessage()
			upstreamReadMu.Unlock()

			if rerr != nil {
				log.Printf("[proxy] upstream read error: %v", rerr)
				if tryUpstreamReconnect(ctx, &upstreamConn, hdr, proto, &upstreamReadMu, &upstreamWriteMu) {
					continue
				}
				recordFailure(ctx, proto)
				errChan <- rerr
				return
			}

			clientWriteMu.Lock()
			clientConn.SetWriteDeadline(time.Now().Add(writeTimeout)) // write deadline for proxy write
			werr := clientConn.WriteMessage(mt, msg)
			clientWriteMu.Unlock()

			if werr != nil {
				log.Printf("[proxy] forward to client failed: %v", werr)
				errChan <- werr
				return
			}
		}
	}()

	// Wait for either direction to fail and ensure both are closed
	select {
	case <-ctx.Done():
		log.Printf("[proxy] context canceled, shutting down")
		closeOnce.Do(closeFunc)
		return ctx.Err()
	case err := <-errChan:
		log.Printf("[proxy] proxy session ending with error: %v", err)
		closeOnce.Do(closeFunc)
		return err
	}
}

// Attempts to dial a fresh upstream and swap it in place
func tryUpstreamReconnect(ctx context.Context, connPtr **websocket.Conn, hdr http.Header, proto string, upstreamReadMu *sync.Mutex, upstreamWriteMu *sync.Mutex) bool {
	if isCircuitOpen(proto) {
		return false
	}

	id := connIDFrom(ctx)
	log.Printf("[conn=%s proto=%s] attempting reconnect…", id, proto)

	for i := 0; i < dialRetryMax; i++ {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		newConn, _, err := websocket.DefaultDialer.Dial(upstreamWSURL, hdr)
		if err != nil {
			log.Printf("[conn=%s proto=%s] dial failure: %v", id, proto, err)
			proxyRetries.WithLabelValues(proto).Inc()
			time.Sleep(dialRetryInterval)
			continue
		}

		// lock both readers and writers while swapping
		upstreamReadMu.Lock()
		upstreamWriteMu.Lock()
		(*connPtr).Close()
		*connPtr = newConn
		upstreamWriteMu.Unlock()
		upstreamReadMu.Unlock()
		resetCircuit(proto)
		log.Printf("[conn=%s proto=%s] upstream reconnected", id, proto)
		return true
	}
	return false
}

// Periodically probes the upstream and resets circuit breaker on success
func upstreamHealthCheck() {
	ticker := time.NewTicker(cbHealthInterval)
	defer ticker.Stop()
	for range ticker.C {
		conn, _, err := websocket.DefaultDialer.Dial(upstreamWSURL, nil)
		if err != nil {
			healthFail.Inc()
			continue
		}
		conn.Close()
		healthSuccess.Inc()
		cbMutex.Lock()
		cbFailureCount = 0
		cbOpenUntil = time.Time{}
		cbMutex.Unlock()
		log.Println("Upstream healthy; circuit closed")
	}
}

// Returns true if circuit breaker is open
func isCircuitOpen(proto string) bool {
	cbMutex.Lock()
	defer cbMutex.Unlock()
	if cbFailureCount < cbThreshold {
		return false
	}
	if time.Now().Before(cbOpenUntil) {
		return true
	}
	// half-open window: allow one test
	cbOpenUntil = time.Time{} // clear open state
	return false
}

// Increments failure count and opens circuit if threshold exceeded
func recordFailure(ctx context.Context, proto string) {
	id := connIDFrom(ctx)

	cbMutex.Lock()
	defer cbMutex.Unlock()
	cbFailureCount++

	if cbFailureCount >= cbThreshold {
		cbOpenUntil = time.Now().Add(cbOpenDuration)
		circuitOpenCount.WithLabelValues(proto).Inc() // instrument circuit opens per proto
		log.Printf("[conn=%s proto=%s] circuit opened for %v after %d failures",
			id, proto, cbOpenDuration, cbFailureCount)
	}
}

// Clears failure count and open state
func resetCircuit(proto string) {
	cbMutex.Lock()
	defer cbMutex.Unlock()
	cbFailureCount = 0
	cbOpenUntil = time.Time{}
	circuitOpenCount.WithLabelValues(proto).Add(0) // ensure metric exists
}

func connIDFrom(ctx context.Context) string {
	if v := ctx.Value(ctxKeyConnID); v != nil {
		return v.(string)
	}
	return "unknown"
}
