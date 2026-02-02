# Security Posture Platform

A local, containerised **security posture and observability lab** that demonstrates how security and reliability signals flow from running services → **OpenSearch** → **derived asset posture** → **Grafana dashboards**.

The project focuses on **how security platforms are built internally** (CSPM, ASM, SIEM-lite), not just how dashboards are consumed.

Everything runs locally using **Docker Compose**, is easy to inspect and break, and mirrors real internal security tooling patterns.

---

## Key characteristics

* Fully local (`127.0.0.1` only)
* Event-driven (raw signals → derived posture)
* Asset-centric (one current state per asset)
* Cron-driven (no Prometheus required)
* Grafana dashboards **provisioned as code**

---

## What’s running

| Service            | Purpose                                 | Port |
| ------------------ | --------------------------------------- | ---- |
| API (FastAPI)      | Core backend + health endpoint          | 8000 |
| PostgreSQL         | Asset inventory & metadata              | 5432 |
| OpenSearch         | Events + derived asset status           | 9200 |
| Grafana            | Dashboards & visualisation              | 3001 |
| Juice Shop         | Intentionally vulnerable demo target    | 3000 |
| verify-web (nginx) | Domain / ownership verification service | 8081 |

All services are **local-only**. Nothing is exposed externally.

---

## High-level architecture

```
+-----------+
|  Clients  |
+-----------+
      |
      v
+-------------+        +-------------------+
|   FastAPI   | -----> |   OpenSearch       |
|   (health)  |        |                   |
+-------------+        | - secplat-events  |
      |                | - secplat-asset-  |
      |                |   status          |
      v                +-------------------+
+---------------+                |
|  PostgreSQL   |                v
|  (assets)     |          +-----------+
+---------------+          |  Grafana  |
                           +-----------+
```

Supporting components:

* **verify-web**: static nginx service for ownership verification
* **cron jobs**: continuously emit health signals and rebuild asset posture

---

## Getting started

### Prerequisites

* Linux / Ubuntu
* Docker Engine
* Docker Compose v2

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

# OpenSearch availability
curl http://localhost:9200 | head

# Domain verification token
curl http://localhost:8081/.well-known/secplat-verification.txt
```

All three should return successful responses.

---

## Domain / ownership verification

The platform exposes a **well-known verification path**, similar to real SaaS security tools.

```
/.well-known/secplat-verification.txt
```

Source in repo:

```
infra/verify-web/.well-known/secplat-verification.txt
```

This demonstrates how **asset ownership or control can be verified** before monitoring or scanning is allowed.

---

## Event ingestion (raw signals)

### Event index

All health signals are written to:

```
secplat-events
```

Example document:

```json
{
  "@timestamp": "2026-02-02T17:45:09Z",
  "service": "api",
  "asset": "secplat-api",
  "level": "health",
  "status": "up",
  "status_num": 1,
  "code": 200,
  "latency_ms": 46
}
```

Signals are intentionally **raw and append-only**.

---

## Asset posture (derived state)

A separate index represents **current posture per asset**:

```
secplat-asset-status
```

Key properties:

* **One document per asset**
* Continuously rebuilt
* Represents *current state*, not history

### Posture states

| State   | status_num | Meaning                    |
| ------- | ---------- | -------------------------- |
| UP      | `1`        | Asset responding normally  |
| STALE   | `0`        | No recent health events    |
| UNKNOWN | `-1`       | No health events ever seen |
| DOWN    | `-2`       | Explicit failure detected  |

Example document:

```json
{
  "asset_key": "verify-web",
  "status": "up",
  "status_num": 1,
  "code": 200,
  "latency_ms": 12,
  "last_seen": "2026-02-02T17:45:09Z"
}
```

This mirrors how real security platforms **collapse events into posture**.

---

## Cron-based health monitoring

Two cron jobs drive the platform:

### 1) Health signal ingestion

```
scripts/health_to_opensearch.sh
```

* Probes API, external web assets
* Measures latency
* Emits health events into `secplat-events`

Cron entry:

```cron
* * * * * /home/labuser/security-posture-platform/scripts/health_to_opensearch.sh >/dev/null 2>&1
```

---

### 2) Asset posture builder

```
scripts/build_asset_status.sh
```

* Reads asset inventory
* Pulls latest health events
* Computes UP / STALE / UNKNOWN / DOWN
* Upserts into `secplat-asset-status`

Cron entry:

```cron
* * * * * /home/labuser/security-posture-platform/scripts/build_asset_status.sh >> /tmp/secplat_build_asset_status.log 2>&1
```

This decouples **signal generation** from **posture evaluation**.

---

## Grafana dashboards

Grafana runs at:

```
http://localhost:3001
```

### Provisioned dashboards

Dashboards are **provisioned as code** and auto-loaded on startup:

```
infra/grafana/dashboards/secplat-posture.json
infra/grafana/provisioning/dashboards/dashboards.yaml
```

No manual UI setup is required after restart.

---

## Asset posture dashboard (current)

The main dashboard includes:

* **Healthy Assets** (UP)
* **Stale Assets**
* **Unknown Assets**
* **Down Assets**
* **Current Asset Posture Table**

Key characteristics:

* Uses **Metric → Count** (no transform hacks)
* Uses Lucene filters on `status_num`
* Time-range aware
* One-row-per-asset posture view

This reflects how SOC and platform teams monitor **fleet-level health**.

---

## Development workflow

Common commands:

```bash
# View logs
docker compose logs -f api

# Restart Grafana
docker compose restart grafana

# Validate compose file
docker compose config > /dev/null && echo "compose ok"
```

---

## Security notes

* All ports are bound to `127.0.0.1`
* OpenSearch security plugins disabled (local lab)
* Grafana credentials configurable via `.env`

This repository is a **learning and experimentation environment**, not a hardened production deployment.

---

## Why this project exists

This project demonstrates:

* How security signals are generated
* How events are indexed
* How posture is derived
* How assets are tracked
* How dashboards are provisioned
* How real security platforms are structured internally

If you can reason about this system, you can reason about **CSPM, ASM, SIEM, and internal security tooling** used in real organisations.

