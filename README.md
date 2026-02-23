# istio-doctor 🩺

**Production-grade Istio debugging utility for large-scale Kubernetes clusters.**

Purpose-built for clusters with 2000+ nodes and 50,000+ pods. Runs parallel data collection, provides end-to-end traffic path tracing, and gives actionable remediation guidance.

---

## Features

| Command | Description |
|---------|-------------|
| `summary` | Real-time mesh health dashboard — runs in seconds on any cluster size |
| `check controlplane` | Istiod health, xDS push latency, sync state across all proxies |
| `check gateway` | Ingress/egress gateway CR validation, TLS config, routing correctness |
| `check dataplane` | Per-proxy sync state, version skew, circuit breaker trips |
| `check config` | Orphaned VirtualServices, DestinationRule/mTLS conflicts, ServiceEntry issues |
| `trace` | End-to-end traffic path tracing with hop-by-hop PASS/WARN/FAIL |
| `audit authz` | AuthZ policy static analysis + specific traffic evaluation |
| `simulate -f policy.yaml` | Dry-run impact analysis before applying AuthZ policies |
| `report` | Full cluster report (JSON/table/Prometheus output) |

---

## Installation

```bash
# From source
git clone https://github.com/yourorg/istio-doctor
cd istio-doctor
make install

# Binary (Linux amd64)
curl -Lo istio-doctor https://github.com/yourorg/istio-doctor/releases/latest/download/istio-doctor-linux-amd64
chmod +x istio-doctor && sudo mv istio-doctor /usr/local/bin/

# Docker
docker run --rm -v ~/.kube:/root/.kube ghcr.io/yourorg/istio-doctor summary
```

### Requirements

- Go 1.22+ (to build)
- `kubectl` access to the target cluster
- RBAC: `get`, `list` on pods, services, endpoints, networkpolicies + all Istio CRDs
- For proxy collection: `exec` permission on pods (or use `--no-proxy-exec` mode)

---

## Quick Start

```bash
# Cluster-wide health dashboard
istio-doctor summary

# Deep checks
istio-doctor check
istio-doctor check controlplane
istio-doctor check gateway

# Trace why checkout can't reach orders-api
istio-doctor trace \
  --from payments/checkout-7d9c8f-xyz \
  --to payments/orders-api:8080 \
  --path /api/orders \
  --method POST

# Trace external traffic through egress gateway
istio-doctor trace \
  --from payments/checkout-7d9c8f-xyz \
  --to api.stripe.com:443 \
  --egress

# Audit all AuthZ policies in a namespace
istio-doctor audit authz -n payments

# Evaluate specific traffic
istio-doctor audit authz \
  --from spiffe://cluster.local/ns/payments/sa/checkout \
  --to-service orders-api \
  --to-port 8080 \
  --to-path /api/orders \
  --to-method POST

# Simulate policy impact before applying
istio-doctor simulate -f new-deny-policy.yaml

# Full JSON report
istio-doctor report -o json --out-file /tmp/mesh-report.json
```

---

## Architecture

```
istio-doctor/
├── cmd/                        # CLI commands (cobra)
│   ├── root.go                 # Global flags, client init
│   ├── summary.go              # Cluster dashboard
│   ├── check.go                # Health checks
│   ├── trace.go                # Traffic path tracer
│   ├── audit.go                # Policy audit
│   ├── simulate.go             # Policy impact simulator
│   └── report.go               # Full report generation
├── pkg/
│   ├── client/
│   │   └── client.go           # K8s + Istio client wrappers
│   ├── collector/
│   │   ├── controlplane.go     # Istiod health, xDS sync via debug endpoints
│   │   ├── proxy.go            # Parallel Envoy admin API collection
│   │   └── policy.go           # All Istio + K8s policy resources
│   ├── analyzer/
│   │   ├── authz.go            # Full AuthZ policy evaluation engine
│   │   ├── connectivity.go     # Hop-by-hop traffic path analysis
│   │   ├── gateway.go          # Gateway CR validation
│   │   ├── config.go           # Config misconfigurations
│   │   └── simulator.go        # Policy impact simulation
│   └── output/
│       └── formatter.go        # table/json/yaml/prometheus output
└── profiles/
    └── default.yaml            # Named check profiles
```

### Performance Design

At 50k+ pods, naive approaches fail. istio-doctor uses:

- **Bounded parallel collection**: Semaphore-limited goroutines per pod (configurable `--workers`)
- **Direct API access**: Hits istiod's `/debug/syncz` and Envoy admin API directly instead of shelling to `istioctl` per pod
- **Informer-compatible**: K8s client tuned with high QPS/Burst for large clusters
- **Scoped queries**: All commands support `--namespace` and label selectors

---

## Common Workflows

### "Why can't service A talk to service B?"

```bash
# Quick trace
istio-doctor trace --from payments/checkout-abc123 --to payments/orders-api:8080

# Or evaluate by identity
istio-doctor audit authz \
  --from spiffe://cluster.local/ns/payments/sa/checkout \
  --to-service orders-api --to-port 8080
```

Output shows exactly which hop failed and the exact resource causing it.

### "Is my new policy safe to apply?"

```bash
istio-doctor simulate -f new-policy.yaml
```

Shows every traffic flow that would be newly blocked or allowed before you apply.

### "Something is wrong with the mesh after a rollout"

```bash
# Check control plane first
istio-doctor check controlplane

# Then check data plane sync
istio-doctor check dataplane --stale-threshold 30
```

### "Audit security posture of the payments namespace"

```bash
istio-doctor audit authz -n payments -o json | jq '.findings[] | select(.severity=="CRITICAL")'
```

---

## Output Formats

```bash
# Human-readable table (default)
istio-doctor check

# JSON (for pipelines, alerting)
istio-doctor check -o json

# Prometheus metrics (for pushing to Alertmanager)
istio-doctor report -o prometheus

# Export to file
istio-doctor report -o json --out-file /tmp/report.json
```

---

## RBAC Requirements

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: istio-doctor
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints", "namespaces", "nodes"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/exec", "pods/portforward"]
  verbs: ["create"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list"]
- apiGroups: ["security.istio.io"]
  resources: ["authorizationpolicies", "peerauthentications", "requestauthentications"]
  verbs: ["get", "list"]
- apiGroups: ["networking.istio.io"]
  resources: ["virtualservices", "destinationrules", "gateways", "serviceentries", "sidecars", "envoyfilters"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list"]
```

---

## Configuration

```yaml
# ~/.istio-doctor.yaml
workers: 100          # Parallel collectors
timeout: 60           # Timeout per command (seconds)
output: table         # Default output format
stale-threshold: 30.0 # Proxy stale threshold (seconds)
```

All settings can be overridden via flags or `ISTIO_DOCTOR_*` environment variables.

---

## Known Limitations

1. **AuthZ evaluation at analysis time**: When evaluating specific traffic, `when` conditions (custom headers, JWT claims) are not evaluated since they require runtime context. The tool will note when conditions exist but cannot evaluate them.

2. **EnvoyFilter effects**: EnvoyFilters can modify Envoy behavior in arbitrary ways. The tool detects their presence and warns about potentially interfering filters, but cannot fully model their impact.

3. **External service reachability**: The tool validates ServiceEntry registration and DestinationRule TLS config but cannot verify actual network reachability to external hosts (firewall rules, DNS resolution at the kernel level, etc.).

4. **Large clusters**: On clusters with >50k pods, proxy data collection (`check dataplane`) may take 2-5 minutes depending on `--workers`. Control plane and policy checks complete in seconds.
