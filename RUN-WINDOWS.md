# Running SecPlat on Windows

No WSL or bash required. Everything runs in Docker; ingestion scripts run inside the `secplat-ingestion` container.

## 1. Prerequisites

- **Docker Desktop** for Windows (with WSL2 backend or Hyper-V).
- Ensure ports are free: 5432, 9200, 3000, 3001, 8000, 8081 (or set them in `.env`).

## 2. Environment

Copy `env.example` to `.env` in the project root and adjust if needed:

```powershell
copy env.example .env
```

## 3. Start the stack

From PowerShell or CMD in the repo root:

```powershell
docker compose up -d --build
docker compose ps
```

Wait until all services are up (especially `secplat-opensearch` and `secplat-api`). The **ingestion** container will wait for API and OpenSearch, then run health + posture scripts every 60 seconds and seed default assets if the API has none.

## 4. Sanity checks

```powershell
curl http://localhost:8000/health
curl http://localhost:9200
curl http://localhost:8081/.well-known/secplat-verification.txt
```

- API: http://localhost:8000  
- Grafana: http://localhost:3001  
- OpenSearch: http://localhost:9200  

## 5. Fresh database (migrations)

If this is a **new** Postgres volume, run the schema migrations once so the API has the full `assets` schema (e.g. `asset_key`, `asset_type`, etc.):

```powershell
Get-Content infra\postgres\migrations\001_assets_v1.sql -Raw | docker compose exec -T postgres psql -U secplat -d secplat
Get-Content infra\postgres\migrations\002_assets_extend.sql -Raw | docker compose exec -T postgres psql -U secplat -d secplat
```

Use your `POSTGRES_USER` and `POSTGRES_DB` from `.env`. If the API already returns assets with `asset_key`, migrations are already applied.

## 6. Logs

```powershell
docker compose logs -f ingestion
docker compose logs -f api
```

## 7. Running the frontend locally (optional)

If you run the frontend with `npm run dev` in `services/frontend` (instead of using the Dockerized frontend), it will try to reach the API at **http://127.0.0.1:8000**. Ensure the API is running (e.g. `docker compose up -d` so the API container is on 8000). To use a different API URL, create `services/frontend/.env.local` with:

```
API_URL=http://127.0.0.1:8000
```

## 8. Stop

```powershell
docker compose down
```

To remove volumes as well: `docker compose down -v`.
