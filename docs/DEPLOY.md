# Deploying SecPlat to a server (production)

This guide gets the full SecPlat app running on a Linux server with a real
domain and automatic HTTPS, for **$0** on Oracle Cloud's Always-Free tier. When
you're done, the "Open the platform" buttons on your landing page can point at a
live, working product.

**Architecture:** a [Caddy](https://caddyserver.com) reverse proxy terminates
HTTPS (free Let's Encrypt cert, auto-renewed) and forwards to the frontend. The
API and datastores stay on `127.0.0.1` / the internal Docker network — only ports
80 and 443 are exposed to the internet.

```
internet ──443──> Caddy ──> frontend:3000 ──> api:8000 ──> postgres / opensearch / redis
```

---

## 1. Provision the server

OpenSearch needs real RAM, so use an instance with **at least 8 GB** (16+ GB is
comfortable).

- **Oracle Cloud (free):** create an **Ampere A1 (ARM)** "Always Free" compute
  instance — you can allocate up to 4 OCPUs / 24 GB RAM at no cost. Do **not**
  use the tiny x86 "micro" instances (1 GB) — OpenSearch won't start.
- **Any other VPS** works too (Hetzner, DigitalOcean, etc.) if you'd rather not
  use Oracle.

Use **Ubuntu 22.04 LTS**. SSH in as a sudo user.

### Open the firewall

Allow inbound **80** and **443** in **two** places:

1. **Oracle Cloud console:** VCN → Security Lists → add ingress rules for TCP
   80 and 443 from `0.0.0.0/0`.
2. **On the VM:**
   ```bash
   sudo ufw allow 80,443/tcp
   sudo ufw allow OpenSSH
   sudo ufw enable
   ```

---

## 2. Install Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
# log out and back in so the group applies, then verify:
docker compose version
```

### OpenSearch kernel requirement (important)

OpenSearch needs a raised memory-map limit or its container will crash-loop:

```bash
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-opensearch.conf
sudo sysctl -p /etc/sysctl.d/99-opensearch.conf
```

---

## 3. Point your domain at the server

Pick a subdomain, e.g. `app.yourdomain.com`, and add a DNS **A record** →
your server's public IP.

> **If your DNS is on Cloudflare:** set this record to **DNS only (grey cloud),
> not proxied (orange cloud).** Caddy needs to answer the Let's Encrypt challenge
> directly. You can switch it to proxied later once the cert is issued, but
> grey-cloud is the simplest reliable setup.

Confirm it resolves before continuing:

```bash
dig +short app.yourdomain.com   # should print your server IP
```

---

## 4. Get the code and configure secrets

```bash
git clone https://github.com/viss2423/security-posture-platform
cd security-posture-platform

cp .env.prod.example .env
nano .env    # fill in EVERY value — see below
```

At minimum you must set, in `.env`:

| Variable | What |
|----------|------|
| `SECPLAT_DOMAIN` | `app.yourdomain.com` (must match the DNS record) |
| `ACME_EMAIL` | your email (Let's Encrypt notices) |
| `ADMIN_PASSWORD` | a strong admin password (or `ADMIN_PASSWORD_HASH`) |
| `API_SECRET_KEY` | `openssl rand -hex 32` |
| `POSTGRES_PASSWORD`, `POSTGRES_RUNTIME_PASSWORD` | strong values |
| `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | strong (upper/lower/digit/symbol) |

`ENV=prod` is already set — with it, the API refuses to start on the default
`admin` password, which is your safety net. Full checklist: [SECURITY.md](../SECURITY.md).

---

## 5. Launch

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

First boot takes a few minutes (image builds + OpenSearch startup). Watch it:

```bash
docker compose ps
docker compose logs -f caddy      # watch the TLS certificate get issued
```

When Caddy logs `certificate obtained successfully`, open
**https://app.yourdomain.com** — you should get the login page over HTTPS with a
valid padlock. Sign in as `admin` with the password you set, or use **Create an
account** for a demo sandbox.

---

## 6. Connect the landing page to it

Your Cloudflare Pages landing page's buttons currently point at GitHub. Now that
the app is live, point them at it:

1. Cloudflare dashboard → your Pages project → **Settings → Environment
   variables**.
2. Add `VITE_APP_URL = https://app.yourdomain.com`.
3. Redeploy (Deployments → Retry, or push any commit).

The "Open the platform" buttons now go straight to your live app.

---

## 7. Operations

**Update to the latest code:**
```bash
cd security-posture-platform
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

**Back up the database** (asset inventory, users, findings, audit log):
```bash
docker exec secplat-postgres pg_dump -U secplat secplat | gzip > backup-$(date +%F).sql.gz
```

**View logs / restart:**
```bash
docker compose logs -f api
docker compose -f docker-compose.yml -f docker-compose.prod.yml restart
```

**Stop everything:**
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml down
```

---

## Notes & optional extras

- **Self-service signup** is on by default (great for a public demo). To make it
  invite-only, set `ALLOW_SELF_REGISTRATION=false` in `.env` and restart.
- **Grafana dashboards** are optional and off by default. If you enable the
  `observability` profile, the embedded dashboard URL is baked at build time
  (`NEXT_PUBLIC_GRAFANA_URL`) — set it to your public Grafana URL and rebuild if
  you want the Dashboards page to work for remote users.
- **Hardening:** re-read [SECURITY.md](../SECURITY.md) once you're live — it
  covers backups, retention, and turning off anything you don't need.
- **Managed option:** don't want to run this yourself? See [COMMERCIAL.md](../COMMERCIAL.md).
