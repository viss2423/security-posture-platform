# SecPlat Helm Chart

This chart is the supported Phase 3 install surface for single-tenant SecPlat deployments.

## Install

```bash
helm upgrade --install secplat charts/secplat \
  --namespace secplat \
  --create-namespace \
  --values my-values.yaml
```

The chart now supports a self-contained single-tenant install with bundled `postgres`, `redis`, and `opensearch` by default. Override images and secrets for your environment.

Minimum required overrides:

- `images.api`
- `images.frontend`
- `images.workerWeb`
- `images.correlator`
- `images.deriver`
- `images.notifier`
- `images.ingestion`
- `secretData.API_SECRET_KEY`
- `secretData.ADMIN_PASSWORD`

For Docker Desktop quickstart validation, use:

```bash
helm upgrade --install secplat charts/secplat \
  --namespace secplat \
  --create-namespace \
  --values charts/secplat/examples/docker-desktop-values.yaml
```

The Docker Desktop example keeps the chart self-contained by bundling `postgres`, `redis`, and `opensearch`, and disables worker HPA so `metrics-server` is not required for the local validation path.

## Upgrade

```bash
helm upgrade secplat charts/secplat \
  --namespace secplat \
  --values my-values.yaml
```

After every upgrade:

1. Verify the API deployment is ready.
2. Verify the frontend service serves `/login`.
3. Sign in and complete the onboarding smoke flow in `/onboarding`.
4. Confirm config or secret changes rolled the workloads and are visible in the new pods.
