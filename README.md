# Security Posture Platform

A local, containerised **security posture & observability lab** that demonstrates how application signals flow from services → OpenSearch → Grafana, with basic domain verification and health monitoring.

This repo is intentionally **developer‑first**: everything runs locally via Docker Compose, ports are bound to `127.0.0.1`, and the stack is easy to inspect, break, and extend.

---

## What’s running

| Service            | Purpose                                    | Port (localhost) |
| ------------------ | ------------------------------------------ | ---------------- |
| API                | Core backend (FastAPI)                     | `8000`           |
| PostgreSQL         | Relational storage                         | `5432`           |
| OpenSearch         | Event & findings store                     | `9200`           |
| Grafana            | Dashboards & visualisation                 | `3001`           |
| Juice Shop         | Intentionally vulnerable app (demo target) | `3000`           |
| verify‑web (nginx) | Domain / ownership verification            | `8081`           |

> All services are bound to **localhost only**. Nothing is exposed externally.

---

## High‑level architecture

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

Additional components:

* **verify‑web**: static nginx site serving a verification token
* **cron health pinger**: writes API health events into OpenSearch every minute

---

## Getting started

### Prerequisites

* Ubuntu / Linux
* Docker Engine + Docker Compose v2

### Start the stack

```bash
cd security-posture-platform
docker compose up -d --build
docker compose ps
```

### Sanity checks

```bash
# API
curl http://localhost:8000/health

# OpenSearch
curl http://localhost:9200 | head

# Verification token
curl http://localhost:8081/.well-known/secplat-verification.txt
```

---

## Domain / ownership verification

The `verify-web` service exposes a well‑known path:

```
/.well-known/secplat-verification.txt
```

Location in repo:

```
infra/verify-web/.well-known/secplat-verification.txt
```

This pattern mirrors real‑world SaaS domain verification flows (e.g. CSPM / ASM tools).

---

## Grafana dashboards

Grafana is available at:

```
http://localhost:3001
```

### Provisioned assets

* **Datasource**: OpenSearch (via Elasticsearch-compatible API)
* **Dashboards**: auto‑loaded from `infra/grafana/dashboards/`

A placeholder dashboard is included to verify provisioning works before real data exists.

---

## OpenSearch event ingestion

### Test index

Events are written to:

```
secplat-events
```

Example document:

```json
{
  "@timestamp": "2026-01-29T00:00:00Z",
  "service": "api",
  "level": "health",
  "message": "healthcheck",
  "status": "up",
  "code": 200
}
```

---

## API health monitoring (cron → OpenSearch)

A lightweight cron job writes API health pings into OpenSearch every minute.

### Script

```
scripts/health_to_opensearch.sh
```

### Cron entry

```cron
* * * * * /home/labuser/security-posture-platform/scripts/health_to_opensearch.sh >/dev/null 2>&1
```

This enables:

* **API uptime panels** in Grafana
* No Prometheus required
* Simple, observable heartbeat

---

## Security notes (important)

* All ports are bound to `127.0.0.1`
* OpenSearch security plugins are currently **disabled** for local development
* Grafana admin credentials should be changed via `.env`

This is a **lab / learning environment**, not a hardened production deployment.

---

## Development workflow

Common commands:

```bash
# View logs
docker compose logs -f api

# Restart a service
docker compose restart grafana

# Validate compose file
docker compose config > /dev/null && echo "compose ok"
```

---

## Next steps / ideas

* Push real API findings into OpenSearch
* Build dashboards for:

  * Findings by severity
  * Assets discovered
  * Scan durations
* Enable OpenSearch security (auth + TLS)
* Add alerting (Grafana or OpenSearch)

---

## Why this project exists

This repo is designed to **show how security tooling is built**, not just used:

* how signals are generated
* how they’re indexed
* how they’re visualised
* how basic trust & verification mechanisms work

If you can reason about this stack, you can reason about real CSPM / ASM / SIEM platforms.

---

✨ Happy breaking & building.
