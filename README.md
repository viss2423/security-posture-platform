# Security Posture Platform

A local, containerised **security posture and observability lab** that demonstrates how security and reliability signals flow from running services → **OpenSearch** → **derived asset posture** → **Grafana dashboards + alerts**.

The goal is to show **how security platforms are built internally** (CSPM / ASM / SIEM-lite), not just how dashboards are used.

Everything runs locally using **Docker Compose**, is easy to inspect and break, and mirrors real internal security tooling patterns.

---

## Key characteristics

- Fully local (`127.0.0.1` only)
- Event-driven (raw signals → derived posture)
- Asset-centric (one current state per asset)
- Cron-driven ingestion (no Prometheus required)
- Grafana dashboards provisioned as code

---

## What’s running

| Service            | Purpose                                   | Port |
|--------------------|-------------------------------------------|------|
| API (FastAPI)      | Core backend + health endpoint             | 8000 |
| PostgreSQL         | Asset inventory & metadata                 | 5432 |
| OpenSearch         | Events + derived asset status              | 9200 |
| Grafana            | Dashboards & alerting                      | 3001 |
| Juice Shop         | Intentionally vulnerable demo target       | 3000 |
| verify-web (nginx) | Domain / ownership verification service   | 8081 |
| ingestion          | Runs health + posture scripts in a loop (no host cron) | —    |

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

````

Supporting components:

- **verify-web**: static nginx service for ownership verification
- **ingestion** (container): runs `health_to_opensearch.sh`, `assets_to_opensearch.sh`, `build_asset_status.sh`, etc. every 60s so no host cron is needed (works on Windows)

---

## Getting started

### Prerequisites

- Docker Engine
- Docker Compose v2
- **Linux/Ubuntu**: bash, curl, jq for running scripts on the host (optional; see below).
- **Windows**: No WSL or bash required. All ingestion runs inside the `ingestion` container.

### Start the stack

```bash
cd security-posture-platform
docker compose up -d --build
docker compose ps
```

On **Windows**, this is enough: the `ingestion` service runs the health and posture scripts inside Docker every 60 seconds, so you don't run any scripts on the host. On **Linux**, you can either use the same (recommended) or run the scripts via cron as in the [Continuous ingestion](#continuous-ingestion-cron) section.

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

## OpenSearch indices

### Raw events (append-only)

Health signals are written to:

```
secplat-events
```

Example event:

```json
{
  "@timestamp": "2026-02-02T22:06:01Z",
  "service": "api",
  "asset": "secplat-api",
  "level": "health",
  "status": "up",
  "status_num": 1,
  "code": 200,
  "latency_ms": 32
}
```

### Derived posture (current state per asset)

Current posture is stored in:

```
secplat-asset-status
```

This index contains **one document per asset** (upserted by `asset_key`).

---

## Asset posture model

Posture is represented using:

| State   | status_num | Meaning                    |
| ------- | ---------- | -------------------------- |
| UP      | `1`        | Asset responding normally  |
| STALE   | `0`        | No recent health events    |
| UNKNOWN | `-1`       | No health events ever seen |
| DOWN    | `-2`       | Explicit failure detected  |

### Posture scoring (secplat-asset-status)

Each asset document includes derived scoring fields:

| Field               | Meaning |
| ------------------- | ------- |
| `posture_score`     | 0–100 (0 = bad, 100 = good) |
| `posture_state`     | `green` \| `amber` \| `red` |
| `last_seen`         | Last health event time |
| `staleness_seconds`  | Seconds since last event |
| `last_status_change`| When status last changed |

Scoring logic:

- `status_num == -2` (DOWN) → score `0`, state `red`
- `status_num == -1` (UNKNOWN) → score `0`, state `red`
- `status_num == 1` (UP) and stale (>5 min) → score `60`, state `amber`
- `status_num == 1` and fresh → score `100`, state `green`

---

## Architecture & design principles

- **Events ≠ state** — `secplat-events` is append-only; posture decisions use **current** state in `secplat-asset-status`, not historical queries.
- **Posture is current, not historical** — One document per asset, continuously overwritten by `build_asset_status.sh`.
- **Data model clarity > tooling** — If dashboards are wrong, alerts will be wrong; the pipeline is designed so posture is computed in one place (the script) and dashboards only read it.
- **Alerting** — Explored (e.g. LAST vs MAX reducers); currently **deferred** so the platform can focus on posture intelligence and dashboards first.

---

## Continuous ingestion (cron)

Two cron jobs drive the platform:

### 1) Health signal ingestion

Script:

```
scripts/health_to_opensearch.sh
```

* Probes API, verify-web, and a stable local target (Juice Shop) for repeatable demos
* Measures latency
* Emits health events into `secplat-events`

Example cron entries (run `assets_to_opensearch.sh` first or periodically so `secplat-assets` is populated):

```cron
* * * * * /home/labuser/security-posture-platform/scripts/health_to_opensearch.sh >/dev/null 2>&1
* * * * * /home/labuser/security-posture-platform/scripts/build_asset_status.sh >> /tmp/secplat_build_asset_status.log 2>&1
```

### 2) Asset posture builder

Script:

```
scripts/build_asset_status.sh
```

* Reads assets
* Pulls latest health events from OpenSearch
* Computes UP / STALE / UNKNOWN / DOWN
* Upserts one current-state doc per asset into `secplat-asset-status`

### 3) Validate posture docs (optional)

After ingestion, check that `secplat-asset-status` has the expected posture fields:

```bash
./scripts/validate_posture.sh
```

Requires `jq`. Checks for `posture_score`, `posture_state`, `staleness_seconds`, `last_status_change`, etc.

---

## Posture API

The API exposes current posture (read from OpenSearch):

| Endpoint | Description |
| -------- | ----------- |
| `GET /posture` | List all asset posture documents |
| `GET /posture/summary` | Counts: green, amber, red, and average posture score |
| `GET /posture/{asset_key}` | Posture for one asset |

Example: `curl http://localhost:8000/posture/summary`

---

## Grafana dashboards

Grafana runs at:

```
http://localhost:3001
```

### Provisioned dashboards

Dashboards are provisioned as code and auto-loaded on startup:

* `infra/grafana/dashboards/secplat-posture.json`
* `infra/grafana/provisioning/dashboards/dashboards.yaml`

---

## Alerting

Alerting has been explored (e.g. LAST vs MAX reducers for “broken right now” vs “ever broken”) and is **intentionally paused**. Focus is on posture scoring and dashboards; alerts can be re-enabled later once the data model and panels are stable.

---

## Development workflow

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

This repository is a learning and experimentation environment, not a hardened production deployment.

---

## Why this project exists

This project demonstrates:

* How security signals are generated
* How events are indexed
* How posture is derived
* How assets are tracked
* How dashboards are provisioned
* How alerting turns posture into detection

If you can reason about this system, you can reason about internal security tooling used in real organisations.

---

## Next steps (optional)

* Alerting on stale critical assets
* Asset ownership & criticality weighting
* Findings ingestion beyond health checks
* API exposure of posture data
* Authentication and role separation

