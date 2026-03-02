# SecPlat Kubernetes Baseline (Phase 5)

This folder provides a first-pass Kubernetes baseline for:

- `secplat-api`
- `secplat-deriver`
- `secplat-worker-web` (+ optional HPA)
- `secplat-notifier`
- `secplat-correlator`
- CronJobs for ingestion and report snapshots
- NetworkPolicies and hardened pod/container security context

## Files

- `kustomization.yaml`: applies all resources in this folder
- `secret.example.yaml`: copy to `secret.yaml`, fill values, and apply
- `overlays/docker-desktop/`: local testing overlay that uses local images and host services
- `deployment-*.yaml`: core workloads
- `hpa-worker-web.yaml`: autoscale workers by CPU utilization
- `cronjob-*.yaml`: ingestion and snapshot jobs
- `networkpolicy-*.yaml`: egress controls + in-cluster Postgres ingress restriction

## Apply (Generic Cluster)

```bash
kubectl apply -f infra/k8s/namespace.yaml
kubectl -n secplat apply -f infra/k8s/secret.yaml
kubectl apply -k infra/k8s
```

## Apply (Docker Desktop + local Compose dependencies)

1. Build local images:

```bash
docker compose build api worker-web deriver notifier correlator ingestion
```

2. Ensure dependencies are running on the host:

```bash
docker compose up -d postgres redis opensearch verify-web juiceshop
```

If the full Compose stack is already running, stop app services that bind local API ports to avoid testing the wrong API instance:

```bash
docker compose stop api worker-web deriver notifier correlator frontend scanner ingestion web
```

3. Create secret for local endpoints:

```bash
kubectl apply -f infra/k8s/namespace.yaml
kubectl -n secplat apply -f infra/k8s/overlays/docker-desktop/secret.local.example.yaml
```

Note: `ENV=prod` is set in `secplat-config`, so `ADMIN_PASSWORD` must not be `admin` (or set `ADMIN_PASSWORD_HASH`).
Service identities are also expected in the secret (`SCANNER_SERVICE_*`, `INGESTION_SERVICE_*`, `CORRELATOR_SERVICE_*`), and `CORRELATOR_USER` should match the correlator service identity.

4. Apply the overlay:

```bash
# kubectl apply -k does not support parent-base overlays with default load restrictions.
kubectl kustomize infra/k8s/overlays/docker-desktop --load-restrictor LoadRestrictionsNone | kubectl apply -f -
kubectl -n secplat get pods
```

The overlay rewrites:
- workload images to `security-posture-platform-*:latest`
- `REDIS_URL`/`OPENSEARCH_URL` and ingestion URLs to `host.docker.internal`

## Notes

- Images are placeholders (`ghcr.io/your-org/...`); replace with your registry/tag strategy.
- External Postgres/OpenSearch/Redis is supported by setting URLs/DSNs in `secplat-config` and `secplat-secrets`.
- `networkpolicy-postgres-ingress-from-api.yaml` applies only if Postgres is in-cluster and labeled `app.kubernetes.io/name=postgres`.
- Worker/deriver/notifier/correlator egress policy intentionally omits port `5432`, so they cannot connect to Postgres.
- Egress is segmented per role (`worker`, `deriver`, `notifier`, `correlator`, `ingestion`) to enforce least-privilege network paths.
