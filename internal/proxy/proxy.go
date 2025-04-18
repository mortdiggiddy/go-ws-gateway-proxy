package proxy

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

var upstreamWSURL = func() string {
	if val := os.Getenv("UPSTREAM_WS_URL"); val != "" {
		return val
	}
	// Default to RabbitMQ MQTT-over-WS endpoint
	return "ws://rabbitmq:15675/ws"
}()

var idleTimeout = func() time.Duration {
	if val := os.Getenv("WS_IDLE_TIMEOUT_SECONDS"); val != "" {
		if sec, err := strconv.Atoi(val); err == nil && sec > 0 {
			return time.Duration(sec) * time.Second
		}
	}
	return 60 * time.Second // default
}()

// ProxyWebSocket streams traffic between clientConn and an upstream WebSocket server
// This function is the lifetime of a single proxy session between a client and an 
// upstream WebSocket. It stays alive as long as both parties are connected and talking
// Works seamlessly with:
// RabbitMQ
// EMQX
// Mosquitto with WebSocket bridge
// Any custom WebSocket target
func ProxyWebSocket(clientConn *websocket.Conn, initial []byte, req *http.Request) error {
	u, err := url.Parse(upstreamWSURL)
	if err != nil {
		return err
	}

	// Dial upstream WebSocket server
	upstreamConn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}

	// When ProxyWebSocket(...) returns — for any reason — close the client WebSocket connection.
	defer upstreamConn.Close()
	defer clientConn.Close() // ensure client connection is also closed

	// Forward initial CONNECT packet
	if err := upstreamConn.WriteMessage(websocket.BinaryMessage, initial); err != nil {
		return err
	}

	errChan := make(chan error, 2)

	// Client -> Upstream

	// Each frame (text/binary) is read from one socket and directly forwarded to the other, preserving:
	// WebSocket message boundaries
	// MQTT framing and binary structure
	// Native duplex communication
	// Latency:
    // No parsing: Not decoding or modifying payloads
	// No buffering: Data is immediately forwarded as it's read
	// No context switching: Each direction is handled in a simple goroutine
	// No TLS termination overhead (unless used upstream)
	go func() {
		for {
			// Optional: set read deadline to detect idle clients
			clientConn.SetReadDeadline(time.Now().Add(idleTimeout)) // configurable if needed
			mt, msg, err := clientConn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			err = upstreamConn.WriteMessage(mt, msg)
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	// Upstream -> Client
	go func() {
		for {
			upstreamConn.SetReadDeadline(time.Now().Add(idleTimeout))
			mt, msg, err := upstreamConn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			err = clientConn.WriteMessage(mt, msg)
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	// Wait for either direction to fail and ensure both are closed
	err = <-errChan
	log.Printf("WebSocket proxy closing: %v", err)
	return err
}