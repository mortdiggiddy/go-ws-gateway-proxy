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

1. **Install chart**

   ```bash
   helm repo add myrepo https://your-repo.example.com/charts
   helm install ws-proxy k8s/helm \
        --values k8s/helm/values.yaml
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
  static_configs:
    - targets: ['<pod-ip>:8080']
```

## Cleanup

```bash
kubectl delete -k k8s/overlays/production
kubectl delete -k k8s/base

helm uninstall ws-proxy
```
