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
- `../policy/kyverno/verify-secplat-images.yaml`: admission policy requiring digest-pinned and keyless-verified images

## Render A Production Release Bundle

The base manifests in `infra/k8s` are templates. The supported production path is a rendered release bundle with real digests and a real keyless attestor subject:

```bash
python services/api/scripts/render_release_bundle.py \
  --image-map-json services/api/examples/release-images.example.json \
  --out-dir artifacts/release-bundle \
  --github-repository acme/security-posture-platform

python services/api/scripts/check_k8s_image_pinning.py \
  --repo-root artifacts/release-bundle \
  --k8s-dir infra/k8s \
  --policy-file infra/policy/kyverno/verify-secplat-images.yaml \
  --require-real-digests
```

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

Or run the guarded cutover helper:

```powershell
.\scripts\runtime-lane-cutover.ps1 -To k8s -StopOtherLane
```

3. Create secret for local endpoints:

```bash
kubectl apply -f infra/k8s/namespace.yaml
kubectl -n secplat apply -f infra/k8s/overlays/docker-desktop/secret.local.example.yaml
```

Note: `ENV=prod` is set in `secplat-config`, so `ADMIN_PASSWORD` must not be `admin` (or set `ADMIN_PASSWORD_HASH`).
Service identities are expected in the secret (`SCANNER_SERVICE_*`, `INGESTION_SERVICE_*`, `CORRELATOR_SERVICE_*`), and `CORRELATOR_USER` should match the correlator service identity. `secplat-worker-web` uses the scanner service identity for internal API job-control calls; it does not need a worker Postgres DSN.

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

- This remains a first-pass Kubernetes baseline; use Compose as the default local/dev lane and Kubernetes as the staged/prod lane.
- Do not run Compose app services and SecPlat Kubernetes app workloads in parallel.
- Use `scripts/runtime-lane-cutover.ps1` for preflight-guarded lane switching.
- Baseline right-sizing defaults:
  - `secplat-api` replicas: `1`
  - `secplat-worker-web` replicas: `1`
  - Worker HPA: min `1`, max `4`
  - API background schedulers disabled by default in `secplat-config`
- Images in the base manifests remain placeholders by design; only the rendered release bundle is supported for production installs.
- CI guardrail: `python services/api/scripts/check_k8s_image_pinning.py --repo-root artifacts/release-bundle --k8s-dir infra/k8s --policy-file infra/policy/kyverno/verify-secplat-images.yaml --require-real-digests` enforces non-placeholder digests.
- External Postgres/OpenSearch/Redis is supported by setting URLs/DSNs in `secplat-config` and `secplat-secrets`.
- Use a least-privilege runtime credential in `API_POSTGRES_DSN` (for example `secplat_runtime`).
- Keep schema-change privileges isolated to `API_MIGRATIONS_POSTGRES_DSN` (admin/migrator DSN used only by API startup migrations).
- `networkpolicy-postgres-ingress-from-api.yaml` applies only if Postgres is in-cluster and labeled `app.kubernetes.io/name=postgres`.
- Worker/deriver/notifier/correlator egress policy intentionally omits port `5432`, so they cannot connect to Postgres. Worker egress explicitly allows Redis, the API service on `8000`, DNS, and HTTP/S scan targets.
- Egress is segmented per role (`worker`, `deriver`, `notifier`, `correlator`, `ingestion`) to enforce least-privilege network paths.
