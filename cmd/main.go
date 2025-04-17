package main

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/mortdiggiddy/go-ws-gateway/internal/auth"
	"github.com/mortdiggiddy/go-ws-gateway/internal/mqtt"
	"github.com/mortdiggiddy/go-ws-gateway/internal/proxy"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // adjust for production
}

func main() {
	http.HandleFunc("/ws", handleWebSocket)
	log.Println("JWT MQTT Proxy listening on :8080/ws")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}
	defer conn.Close()

	// Step 1: Read initial MQTT CONNECT packet
	_, packet, err := conn.ReadMessage()
	if err != nil {
		log.Println("Failed to read MQTT CONNECT packet:", err)
		return
	}

	// Step 2: Parse MQTT CONNECT to extract JWT
	username, jwtToken, err := mqtt.ParseMQTTConnect(packet)
	
	if err != nil {
		log.Println("MQTT CONNECT parse error:", err)
		conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(1002, "Bad MQTT CONNECT"), r.Context().Done())
		return
	}

	log.Printf("CONNECT from user=%s\n", username)

	// Step 3: Verify JWT
	valid, err := auth.VerifyJWT(jwtToken)
	if !valid || err != nil {
		log.Printf("JWT invalid: %v\n", err)
		conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(1008, "JWT invalid or expired"), r.Context().Done())
		return
	}

	// Step 4: Proxy to RabbitMQ WS MQTT backend
	err = proxy.ProxyToRabbitMQ(conn, packet, r)
	if err != nil {
		log.Println("Proxying failed:", err)
		return
	}
}
