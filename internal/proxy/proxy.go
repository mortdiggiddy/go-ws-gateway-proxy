package proxy

import (
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
)

var rabbitURL = "ws://rabbitmq:15675/ws"

func ProxyToRabbitMQ(clientConn *websocket.Conn, initial []byte, req *http.Request) error {
	u, err := url.Parse(rabbitURL)
	if err != nil {
		return err
	}

	// Dial RabbitMQ
	rmqConn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	defer rmqConn.Close()

	// Forward initial MQTT CONNECT packet
	if err := rmqConn.WriteMessage(websocket.BinaryMessage, initial); err != nil {
		return err
	}

	errChan := make(chan error, 2)

	// Client -> RabbitMQ
	go func() {
		for {
			mt, msg, err := clientConn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			if err := rmqConn.WriteMessage(mt, msg); err != nil {
				errChan <- err
				return
			}
		}
	}()

	// RabbitMQ -> Client
	go func() {
		for {
			mt, msg, err := rmqConn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			if err := clientConn.WriteMessage(mt, msg); err != nil {
				errChan <- err
				return
			}
		}
	}()

	return <-errChan
}
