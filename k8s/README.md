# Overview

This deployment package provisions the go-ws-gateway-proxy, a lightweight, high-performance WebSocket reverse proxy written in Go. It is designed to authenticate incoming WebSocket clients via JWT (e.g., from Keycloak), and forward valid connections to an upstream MQTT-over-WebSocket broker such as RabbitMQ. The proxy validates JWTs against a JWKS endpoint and enforces origin-level CORS restrictions.

The proxy supports:

- JWT-based access control
- Connection draining with preStop hook
- Exposed metrics for Prometheus
- Structured logging for EFK stacks
- TLS-terminated WebSocket connections via Traefik Ingress

# go-ws-gateway-proxy Kubernetes Deployment

This directory contains all of the Kubernetes manifests, Kustomize overlays, and a Helm chart needed to deploy the go-ws-gateway-proxy service at enterprise scale. You can choose between Kustomize (recommended for GitOps workflows) or Helm (for templated installs).

---

## Prerequisites

- A Kubernetes cluster (v1.22+)
- `kubectl` (v1.22+) configured to talk to your cluster
- Either:
  - **Kustomize** CLI (v4+)
  - **Helm** v3+
- A working Traefik Ingress (or compatible) listening on `websecure` entrypoint
- Access to a container registry to push `your-registry/go-ws-gateway-proxy:…`

---

## Directory Structure

```bash
k8s/
├── base/
│   ├── configmap.yaml
│   ├── deployment.yaml
│   ├── ingress.yaml
│   ├── kustomization.yaml
│   ├── secret.yaml
│   └── service.yaml
├── overlays/
│   ├── staging/
│   └── production/
├── helm/
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/
│       ├── configmap.yaml
│       ├── deployment.yaml
│       ├── ingress.yaml
│       ├── secret.yaml
│       └── service.yaml
```

The `go-ws-gateway-proxy` deployment provisions the following Kubernetes resources:

| Resource                         | Kind                        | Purpose                                                                                    |
| -------------------------------- | --------------------------- | ------------------------------------------------------------------------------------------ |
| 🧱 **Deployment**                | `apps/v1/Deployment`        | Runs the proxy with configurable replicas, resource limits, probes, and graceful shutdown. |
| 🔌 **Service**                   | `v1/Service`                | Exposes the proxy internally on port `8080` using `ClusterIP`.                             |
| 🌐 **Ingress**                   | `networking.k8s.io/Ingress` | Routes external TLS WebSocket traffic to the `/ws` endpoint (e.g., via Traefik).           |
| ⚙️ **ConfigMap**                 | `v1/ConfigMap`              | Stores non-sensitive runtime configuration like CORS origins, timeouts, and JWKS URL.      |
| 🔐 **Secret**                    | `v1/Secret`                 | Holds sensitive values such as JWT issuer/audience, Redis, Postgres, and upstream target.  |
| ❤️ **Liveness/Readiness Probes** | HTTP `/healthz`             | Ensures the pod is started and serving traffic reliably.                                   |
| 📊 **Metrics Endpoint**          | HTTP `/metrics`             | Exposes Prometheus-compatible metrics for observability.                                   |
| ⏱ **Lifecycle Hook**             | `preStop` script            | Drains in-flight connections with a configurable timeout before pod termination.           |

---

## Configuration

### ConfigMap (`base/configmap.yaml`)

Holds non‑sensitive defaults:

- `WS_ALLOWED_ORIGINS`
- `JWT_COOKIE_NAME`
- Timeouts: `GRACEFUL_DRAIN_TIMEOUT_SECONDS`, `WS_IDLE_TIMEOUT_SECONDS`, `WS_WRITE_TIMEOUT_SECONDS`
- JWKS settings: `JWKS_URL`, `JWKS_TTL_MINUTES`

### Secret (`base/secret.yaml`)

Holds sensitive/runtime data:

- `JWT_EXPECTED_ISSUER`, `JWT_EXPECTED_AUDIENCE`, `JWT_VALID_ALGORITHMS`
- Optional cache endpoints: `REDIS_URL`, `POSTGRES_DSN`
- Upstream target: `UPSTREAM_WS_URL`

> **Tip:** In overlays or your CI/CD pipeline, replace these values with real secrets via sealed‑secrets or your cloud provider’s secret store.

---

## Deploy with Kustomize

Recommended for GitOps-based workflows where manifests are declarative and managed through Git (e.g., Argo CD or Flux CD).

- Encourages layering via overlays (e.g., staging/, production/)
- No templating logic — strict YAML with reusable base
- Secrets and ConfigMaps are managed as first-class citizens

1. **Base deployment**

   ```bash
   kubectl apply -k k8s/base
   ```

2. **Staging overlay**

   ```bash
   kubectl apply -k k8s/overlays/staging
   ```

3. **Production overlay**

   ```bash
   kubectl apply -k k8s/overlays/production
   ```

## Deploy With Helm

Recommended for templated, parameter-driven installations, such as interactive CLI deploys, CI/CD pipelines, or when reusing charts across environments.

- Enables dynamic configuration using values.yaml
- Generates manifests using Go templating
- Suitable for environments with variable parameters (e.g., different ingress hosts or JWKS URLs)

1. **Install chart**

   ```bash
   # Install directly from local directory (no repo add needed)
   helm install ws-proxy ./helm --values ./helm/values.yaml
   # Optional: preview what Helm renders without applying
   helm template ws-proxy ./helm --values ./helm/values.yaml
   ```

2. **Upgrade chart**

   ```bash
    helm upgrade ws-proxy k8s/helm \
        --values your-custom-values.yaml
   ```

3. **Uninstall**
   ```bash
    helm uninstall ws-proxy
   ```

## Health & Observability

- **Liveness/Readiness Probes:**  
  Exposed at `/healthz` to allow Kubernetes to manage pod lifecycle appropriately.

- **Prometheus Metrics Endpoint:**  
  Available at `/metrics` for real-time monitoring and scraping by Prometheus.

- **Structured Logging:**  
  Logs are printed via `log.Printf(...)`, collected using Fluentd and stored/viewed via the EFK (Elasticsearch, Fluentd, Kibana) stack.

- **Graceful Termination:**  
  Uses Kubernetes `preStop` hook with a configurable `GRACEFUL_DRAIN_TIMEOUT_SECONDS` to ensure in-flight connections are closed properly.

---

## Access & Verification

- **Ingress WebSocket URL:**  
  `wss://ws-public-host-name.example.com/ws`

- **Browser Testing via MQTT.js:**

  ```js
  const client = mqtt.connect({
    protocol: 'wss',
    hostname: 'ws-public-host-name.example.com',
    path: '/ws',
    wsOptions: {
      // Note: headers are ignored by browsers due to security restrictions
    },
  });
  ```

### Prometheus Scrape Configuration

```yaml
- job_name: ws-proxy
  kubernetes_sd_configs:
    - role: pod
  relabel_configs:
    - source_labels: [__meta_kubernetes_pod_label_app]
      action: keep
      regex: go-ws-gateway-proxy
```

## Cleanup

```bash
kubectl delete -k k8s/overlays/production
kubectl delete -k k8s/base

helm uninstall ws-proxy
```
