# go-ws-gateway-proxy

A high-performance, secure, and protocol-aware WebSocket gateway designed to handle thousands of concurrent connections—whether MQTT-over-WebSocket or raw WebSocket—in a unified, observable, and production-ready manner.

---

## 🚀 Why This Project Exists

Modern real-time systems demand scalable gateways to ingest connections from heterogeneous clients: robots, IoT devices, mobile apps, telemetry dashboards, and more. These clients often use:

- MQTT-over-WebSocket (for sensor data, telemetry, robotics)
- Raw WebSocket (for JSON RPC, custom protocols, command channels)

You need a gateway that:

- Authenticates clients
- Understands different protocols
- Forwards data transparently and efficiently
- Can be deployed behind TLS ingress layers (like Traefik or NGINX)
- Observes and audits sessions at scale

**This project is that gateway.**

Written in Go for performance and concurrency, it uses:

- `gorilla/websocket` for low-level WebSocket control
- `golang-jwt/jwt/v5` for standards-compliant JWT verification
- Prometheus metrics for real-time observability

---

## 🧠 Design Goals

- ⚡ **Minimal latency**
- 🧵 **Two goroutines per connection** (no context switching)
- 🔐 **JWT-secured access**
- 🔁 **Full-duplex binary & text stream support**
- 🧩 **Multi-protocol support** (MQTT/WS, raw WS, future protocols)
- 📊 **Observability-first** with labeled Prometheus metrics
- 🚦 **Graceful shutdown** for container orchestration
- ☁️ **Cloud-native by default** (Kubernetes, Traefik, Docker)

---

## 🧰 Features

### ✅ Unified Entry Point

Single endpoint (`/ws`) supports both:

- MQTT-over-WebSocket (e.g., RabbitMQ w/ MQTT plugin)
- EMQX
- Mosquitto with WebSocket bridge
- Raw WebSocket clients (e.g., control channels, JSON-RPC, custom frames)

### ✅ Intelligent Protocol Discovery

The gateway uses a lightweight parser to autodetect the protocol:

```go
protocol, username, token, err := ParseConnect(packet)
```

### ✅ Secure JWT Validation

- JWTs extracted from MQTT `password` or raw WS payload
- Validated using JWKS from Keycloak (or any OIDC-compliant provider)
- Claims parsed: `sub`, `preferred_username`, `iat`, `exp`, `jti`

### ✅ Transparent Proxying

- Zero-copy WebSocket forwarding
- No payload parsing or transformation
- Binary or text preserved
- Keeps native framing (e.g., MQTT control packets)

### ✅ Prometheus Metrics

| Metric                                          | Description                         |
| ----------------------------------------------- | ----------------------------------- |
| `ws_total_connections`                          | Total client upgrades attempted     |
| `ws_auth_failures_total`                        | Count of invalid or expired JWTs    |
| `ws_auth_success_total{sub,preferred_username}` | Successful authentications per user |
| `ws_active_sessions`                            | Live connection count               |

### ✅ Traefik- and K8s-Friendly

- TLS termination handled by ingress
- Supports `/healthz` endpoint for liveness checks
- Clean shutdown on `SIGTERM`
- Configurable timeouts (e.g. `WS_IDLE_TIMEOUT_SECONDS`)

### ✅ Extensible Protocol Router

- Future support for GraphQL-over-WS, STOMP, or custom protocol adapters
- Upstreams configurable by protocol (env-driven)

---

## 📦 Project Structure

```bash
.
├── Dockerfile
├── .env.example
├── scripts/
│   └── docker_run.sh
├── internal/
│   ├── mqtt/          # Protocol detection & parsing
│   ├── auth/          # JWT verification via JWKS
│   └── proxy/         # Transparent duplex forwarding
├── main.go            # Entry point
└── README.md
```

---

## 🐳 Running with Docker

### Step 1: Prepare Environment

Copy the `.env.example` file and customize it:

```bash
cp .env.example .env
```

Set values like:

```env
JWKS_URL=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs
WS_IDLE_TIMEOUT_SECONDS=90
UPSTREAM_WS_URL=ws://rabbitmq:15675/ws
RAW_WS_BACKEND_URL=ws://backend-service:8081/raw
```

### Step 2: Run Docker

Use the provided script:

```bash
./scripts/docker_run.sh
```

Which executes:

```bash
docker run --rm \
  -p 8080:8080 \
  --env-file .env \
  go-ws-gateway-proxy
```

### Step 3: Access Metrics & Health

- `http://localhost:8080/metrics`
- `http://localhost:8080/healthz`

---

## 🔮 Future Enhancements

### 🧠 Redis-backed JWT Session Cache

- Cache `jti`, `exp`, and validation results
- Detect token replay or early revocation
- Share across multiple gateway replicas

### 🔀 Multi-Upstream Routing

- Load balance or route by `sub`, `claims`, or protocol
- Separate fleets of robots or services
- Support for sticky sessions by token hash

### 📡 Backpressure & Rate Limiting

- Queue-aware outbound flow control
- Burst protection by identity (`sub`)

### 🔑 Token Introspection Support

- Fallback to OAuth2 `introspection_endpoint`
- For short-lived, reference-based tokens

---

## 🔧 Configuration Options

| Env Var                   | Purpose                     | Default                   |
| ------------------------- | --------------------------- | ------------------------- |
| `JWKS_URL`                | URL for JWKS discovery      | —                         |
| `WS_IDLE_TIMEOUT_SECONDS` | Idle timeout per connection | `60`                      |
| `UPSTREAM_WS_URL`         | MQTT-over-WS backend        | `ws://rabbitmq:15675/ws`  |
| `RAW_WS_BACKEND_URL`      | Raw WebSocket backend       | `ws://localhost:8081/raw` |

---

## 🤝 Contributing

Pull requests, issues, and discussions are welcome. Contributions should maintain zero-dependency, high-performance Go idioms.

---

## 📝 License

MIT License © 2024 — go-ws-gateway-proxy authors

---

## 🧭 Summary

| Feature                      | Value |
| ---------------------------- | ----- |
| Protocol-aware WS proxy      | ✅    |
| Secure JWT auth w/ Keycloak  | ✅    |
| Fast, transparent forwarding | ✅    |
| Metrics, health checks       | ✅    |
| Deployable to K8s, Docker    | ✅    |
| Extensible architecture      | ✅    |

> This gateway is built for real-time systems that care about security, observability, and scale. Whether you’re running a robotics fleet, an IoT mesh, or a trading interface — this is the entry point you can rely on.
