# Security Posture Platform

A local, containerised **security posture and observability lab** that demonstrates how security and reliability signals flow from running services → **OpenSearch** → **Grafana**, with domain ownership verification and continuous health monitoring.

This repository is intentionally **developer-first**:

-- everything runs locally using Docker Compose
-- all services are bound to `127.0.0.1`
-- the stack is easy to inspect, break, debug, and extend

The project is designed to mirror how real security platforms (CSPM, ASM, SIEM-lite tools) are **built internally**, not just how they are used.

---

## What’s running

| Service            | Purpose                              | Port (localhost) |
| ------------------ | ------------------------------------ | ---------------- |
| API (FastAPI)      | Core backend service                 | `8000`           |
| PostgreSQL         | Relational data store                | `5432`           |
| OpenSearch         | Event and signal store               | `9200`           |
| Grafana            | Dashboards and visualisation         | `3001`           |
| Juice Shop         | Intentionally vulnerable demo target | `3000`           |
| verify-web (nginx) | Domain / ownership verification      | `8081`           |

All services are **local-only**. Nothing is exposed externally.

---

## High-level architecture

```
+-----------+        +-------------+        +------------+
|  Clients  | -----> |     API     | -----> | OpenSearch |
+-----------+        +-------------+        +------------+
                             |                     |
                             |                     v
                             |               +-----------+
                             |               |  Grafana  |
                             |               +-----------+
                             v
                      +---------------+
                      |  PostgreSQL   |
                      +---------------+
```

Supporting components:

-- **verify-web**: static nginx service for ownership verification
-- **cron health pinger**: writes API health events into OpenSearch every minute

---

## Getting started

### Prerequisites

-- Linux / Ubuntu
-- Docker Engine
-- Docker Compose v2

### Start the stack

```bash
cd security-posture-platform
docker compose up -d --build
docker compose ps
```

---

## Sanity checks

```bash
# API health
curl http://localhost:8000/health

# OpenSearch
curl http://localhost:9200 | head

# Domain verification token
curl http://localhost:8081/.well-known/secplat-verification.txt
```

All three should return successful responses.

---

## Domain / ownership verification

The platform exposes a **well-known verification path**, similar to real SaaS security products.

Path:

```
/.well-known/secplat-verification.txt
```

Repo location:

```
infra/verify-web/.well-known/secplat-verification.txt
```

This demonstrates how asset ownership or domain control can be verified before scanning or monitoring is allowed.

---

## OpenSearch event ingestion

### Event index

All health signals are written to:

```
secplat-events
```

Example document:

```json
{
  "@timestamp": "2026-01-29T16:22:01Z",
  "service": "api",
  "level": "health",
  "message": "healthcheck",
  "status": "up",
  "status_num": 1,
  "code": 200,
  "latency_ms": 22
}
```

This schema is intentionally simple and extensible.

---

## API health monitoring (cron → OpenSearch)

A lightweight cron job performs a health check against the API every minute and writes the result into OpenSearch.

### Script

```
scripts/health_to_opensearch.sh
```

### Cron configuration

```cron
* * * * * /home/labuser/security-posture-platform/scripts/health_to_opensearch.sh >/dev/null 2>&1
```

This enables:

-- continuous uptime tracking
-- latency measurement
-- failure detection without Prometheus
-- a simple, observable heartbeat

---

## Grafana dashboards

Grafana is available at:

```
http://localhost:3001
```

### Provisioned components

-- OpenSearch datasource (Elasticsearch-compatible API)
-- Dashboards auto-loaded from `infra/grafana/dashboards/`

A placeholder dashboard is included to validate provisioning before real dashboards are built.

---

## Asset health visualisation (current state)

The platform includes a **current-state Asset Health Table** built using Grafana transformations.

Key characteristics:

-- one row per asset
-- shows latest status, latency, HTTP code
-- shows last time the asset was seen
-- derived from raw event data (not pre-aggregated)

This demonstrates how **events are transformed into posture** inside a security platform.

---

## Development workflow

Common commands:

```bash
# View service logs
docker compose logs -f api

# Restart a service
docker compose restart grafana

# Validate compose configuration
docker compose config > /dev/null && echo "compose ok"
```

---

## Security notes

-- All ports are bound to `127.0.0.1`
-- OpenSearch security plugins are disabled for local development
-- Grafana admin credentials are configurable via `.env`

This repository is a **learning and experimentation lab**, not a hardened production deployment.

---

## Why this project exists

This project exists to demonstrate:

-- how security signals are generated
-- how they are indexed
-- how they are visualised
-- how ownership and trust can be enforced
-- how real security platforms are architected

If you can reason about this stack, you can reason about **CSPM, ASM, SIEM, and internal security platforms** used in real organisations.

---

## Planned next steps

-- Full asset inventory (owner, environment, criticality)
-- Asset-aware dashboards and filtering
-- Alerting on asset health degradation
-- Findings ingestion beyond health checks
-- Optional authentication and role separation

---


