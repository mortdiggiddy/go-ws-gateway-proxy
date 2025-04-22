# go-ws-gateway-proxy

A high-performance, secure, and protocol-aware WebSocket gateway designed to handle thousands of concurrent connections—whether MQTT-over-WebSocket or raw WebSocket—in a unified, observable, and production-ready manner.

---

## 🚀 Why This Project Exists

Modern real-time systems demand scalable gateways to ingest connections from heterogeneous clients: robots, IoT devices, mobile apps, telemetry dashboards, and more. These clients often use:

- MQTT-over-WebSocket (for sensor data, telemetry, robotics)
- Raw WebSocket (for JSON RPC, custom protocols, command channels)

While WebSocket is a great transport for bidirectional communication, **many WebSocket backends (like RabbitMQ, EMQX, or internal services) do not provide native authentication or authorization**. This project introduces a secure **middle-layer proxy** that provides:

- **JWT-based authentication** on every incoming connection
- **Protocol detection and dispatching**
- **Observability and metrics**
- **Deployment simplicity behind ingress gateways like Traefik or NGINX**

**Why JWT?**

- Because it's interoperable with any **OIDC-compliant identity provider** (like Keycloak, Auth0, AWS Cognito, Azure AD)
- JWTs can be **embedded in MQTT CONNECT packets**, used as initial messages, or sent in headers in future extensions
- This allows the gateway to be a proper **security enforcement boundary**, even when the backend lacks native identity controls

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

### 🛡️ Secure JWT Validation

- JWTs extracted from MQTT `password` or raw WS payload
- Validated using JWKS from Keycloak (or any OIDC-compliant provider)
- Claims parsed: `sub`, `preferred_username`, `iat`, `exp`, `jti`

This creates a **security envelope** on top of the WebSocket protocol, even when the downstream WebSocket service (like RabbitMQ) lacks native identity enforcement.

### ✅ Transparent Proxying

- Zero-copy WebSocket forwarding
- No payload parsing or transformation
- Binary or text preserved
- Keeps native framing (e.g., MQTT control packets)

### ✅ Rate Limiting

The gateway supports **optional message-level rate limiting** on all active WebSocket connections. This protects against abusive clients, ensures system fairness, and enforces resource boundaries.

- **Configuration:**

  - `RATE_LIMIT_PER_SECOND`: Maximum sustained message rate (refill rate of the token bucket)
  - `RATE_LIMIT_BURST`: Maximum burst capacity (number of messages allowed in a short burst)

- **Behavior:**

  - Enforced using Go’s token bucket algorithm (`golang.org/x/time/rate`)
  - On violation, the gateway sends a standards-compliant control frame:
    ```http
    WebSocket Close Code: 1008 (Policy Violation)
    Reason: Rate limit exceeded
    ```
  - The connection is then closed gracefully

- **Identity-aware enforcement:**

  - For authenticated clients, rate limits are enforced **per JWT subject (`sub`)**
  - For anonymous clients, fallback to **IP address-based limiting**
  - Ensures shared rate control across all concurrent sessions from the same user or client

- **Distributed enforcement via Redis:**
  - When `REDIS_URL` is set, rate limits are enforced across instances using a Redis-backed counter (with 1-second fixed windows)
  - Lua scripting ensures atomicity and correct TTL behavior under load
  - Fallbacks to in-memory limits if Redis is unavailable

### 📈 Prometheus Metrics

📈 Prometheus Metrics

| Metric                                          | Description                                                    |
| ----------------------------------------------- | -------------------------------------------------------------- |
| `ws_connections_total`                          | Total number of WebSocket connections attempted                |
| `ws_auth_failures_total`                        | Count of invalid, expired, or malformed JWTs                   |
| `ws_auth_success_total{sub,preferred_username}` | Successful JWT authentications labeled by subject and username |
| `ws_active_sessions`                            | Currently active WebSocket proxy sessions                      |
| `ws_connection_duration_seconds`                | Histogram of WebSocket session lifetimes (seconds)             |
| `ws_protocol_connections_total{protocol}`       | Total connection count by protocol type (`mqtt`, `raw`, etc.)  |
| `ws_proxy_errors_total{protocol}`               | Total proxy-level failures during streaming                    |
| `ws_proxy_retries_total{protocol}`              | Count of upstream reconnect attempts during proxying           |
| `ws_circuit_open_total{protocol}`               | Count of circuit breaker open events per protocol              |
| `ws_upstream_health_success_total`              | Successful upstream health check responses                     |
| `ws_upstream_health_failure_total`              | Failed upstream health check responses                         |
| `ws_rate_limit_violations_total`                | Number of rate limit violations                                |

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

## 🔧 Architecture

### 1. Direct WebSocket Gateway Model

This shows how a client connects directly to the `go-ws-gateway-proxy`, which validates JWTs and forwards traffic to the backend.

![Basic JWT Proxy Flow](public/go-ws-gateway-1.png)

### 2. Full Deployment with Traefik + Ingress

This shows how the proxy can sit behind a public L4/L7 ingress (e.g., Traefik) and route traffic securely within Kubernetes or a VM-based infrastructure.

![Ingress-Traefik Deployment Flow](public/go-ws-gateway-2.png)

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

First time only:

```bash
chmod +x scripts/docker_run.sh
```

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
