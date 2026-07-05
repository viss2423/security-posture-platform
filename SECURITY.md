# Security

SecPlat is a security product, so we hold the platform itself to the same
standard. This document covers how to run it safely and how to report a
vulnerability.

## Reporting a vulnerability

If you believe you have found a security issue in SecPlat, please **do not open a
public GitHub issue**. Email **vishal.ireland2423@gmail.com** with:

- a description of the issue and its impact,
- steps to reproduce (proof-of-concept if possible),
- the affected version / commit.

You will get an acknowledgement within a few days. Please give a reasonable
window to fix the issue before any public disclosure.

## Safe by default

A default `docker compose up` is safe to run on a laptop for evaluation:

- **Nothing is exposed to the network.** Every published port binds to
  `127.0.0.1`, so only the local machine can reach any service.
- **No phone-home.** The platform sends no telemetry or analytics to the authors.
  All outbound network calls are opt-in and only happen when *you* configure a
  feature (GitHub scanning needs a token, AI enrichment needs `AI_ENABLED=true`,
  threat-intel feeds only refresh when you run that job).
- **No hardcoded secrets** in the source, and secret scanning (gitleaks) runs on
  every commit and in CI.
- **Role isolation.** Self-registered accounts get a read-only demo sandbox and
  cannot see real operator data (see the roles section in the README).

## Hardening checklist for team / production deployments

The convenience defaults are for local evaluation. **Before exposing SecPlat to
anyone other than yourself, do all of the following.**

### 1. Secrets and credentials (required)

- [ ] Set `ENV=prod`. The API refuses to start on the default `admin/admin`
      password when `ENV=prod`.
- [ ] Set a strong admin password via `ADMIN_PASSWORD` or, better,
      `ADMIN_PASSWORD_HASH` (a bcrypt hash — never store the plaintext).
- [ ] Generate a unique `API_SECRET_KEY` (this signs auth tokens):
      `openssl rand -hex 32`. Never ship the value from `.env.example`.
- [ ] Set strong, unique values for `POSTGRES_PASSWORD`,
      `OPENSEARCH_INITIAL_ADMIN_PASSWORD`, and `GRAFANA_ADMIN_PASSWORD`.
- [ ] Keep your real `.env` out of version control (it already is —
      `.gitignore` only allows `.env.example`).

### 2. Network and transport (required)

- [ ] Put SecPlat behind a reverse proxy (nginx, Caddy, or your cloud LB) that
      **terminates TLS**. The app serves plain HTTP; it must not be reached over
      HTTP on an untrusted network.
- [ ] Keep the default `127.0.0.1` port bindings and let only the reverse proxy
      talk to the app. If you change a binding to `0.0.0.0`, you are opting out
      of the safe default — that service is now reachable and must be firewalled.
- [ ] Restrict access to the datastores (`postgres`, `opensearch`) to the
      application network only. They should never be internet-reachable.

### 3. Access control (recommended)

- [ ] Decide on self-registration. `ALLOW_SELF_REGISTRATION` defaults to `true`
      (great for a public demo). Set it to `false` for an internal deployment so
      only admins can create accounts.
- [ ] Configure SSO (OIDC) if your organisation uses it — see the OIDC settings
      in `services/api/app/settings.py`. New SSO users are provisioned as
      viewers by default (`OIDC_AUTO_PROVISION`).
- [ ] Review roles: `viewer` (demo/read-only), `analyst` (operate), `admin`
      (full control incl. user management). Grant the least privilege needed.

### 4. Scanning safety (recommended)

SecPlat can run active scans (web exposure, attack-lab simulations). Guardrails
exist and should stay on:

- [ ] `BLOCK_PRIVATE_IPS=true` and `REQUIRE_DOMAIN_VERIFICATION=true` — only scan
      assets you have proven you control.
- [ ] Keep `MAX_SCAN_DURATION_SECONDS` and `MAX_REQUESTS_PER_SECOND` bounded.
- [ ] `ATTACK_LAB_ALLOWED_NETWORKS` restricts simulation targets to sandboxes —
      keep it tight; never point it at production ranges.

### 5. Data and operations (recommended)

- [ ] Back up the Postgres volume (asset inventory, users, findings, audit log).
- [ ] Set a log/evidence retention policy that matches your compliance needs.
- [ ] The audit trail records who changed what — keep it, it is also SOC 2
      change-management evidence.

## What SecPlat is (and is not)

SecPlat is open-source software provided under the AGPL-3.0 with no warranty (see
[LICENSE](LICENSE)). It has not been independently penetration-tested or
certified. It is a strong, transparent foundation you can self-host and audit —
not a compliance guarantee. If you want a managed, hardened instance run for you,
see [COMMERCIAL.md](COMMERCIAL.md).
