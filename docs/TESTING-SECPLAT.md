# Testing SecPlat (website + API)

Run the stack, then follow these checks. All URLs assume default ports (frontend 3002, API 8000, Grafana 3001).

---

## 1. Start the stack

```powershell
cd c:\Users\visha\Desktop\security-posture-platform
docker compose up -d --build
```

Wait ~1–2 min for ingestion to run at least once (writes to OpenSearch). Check:

```powershell
docker compose ps
```

All services should be `Up`. Optional: `docker logs secplat-ingestion --tail 20` to confirm health checks ran.

---

## 2. Website (main flow)

| Step | Action | Expected |
|------|--------|----------|
| 1 | Open **http://localhost:3002** | Redirect to `/login` |
| 2 | Login: `admin` / `admin` | Redirect to `/overview` |
| 3 | **Overview** | Green/Amber/Red counts, Posture score; if any red, "Down assets" list with links |
| 4 | **Assets** | Table: Asset, Name, Status, Criticality, Score, Owner, Env, Last seen. Owner shows "Unassigned" when empty |
| 5 | Click an asset (e.g. juice-shop) | **Asset detail** page |
| 6 | Asset detail – top | "Last updated Xs ago"; "Expected interval: every 60s"; "Data completeness (24h): N/1440 (X%)"; "Last hour: N/60 (X%)" |
| 7 | Asset detail – state block | Status, Reason, Score, Criticality, Last seen, Staleness, Env, Owner, **Latency SLO** (< 200ms ✓ or > 200ms ✗), **Error rate (24h)** |
| 8 | Asset detail – Recommended actions | At least one line (e.g. "No actions required — asset is healthy.") |
| 9 | Asset detail – Timeline | Table: Time, Status, Code, Latency; rows with code≠200 or latency>200ms highlighted; "spike" badge on high latency |
| 10 | Asset detail – Evidence | JSON block; **Copy JSON** button works; "View in OpenSearch" only if `NEXT_PUBLIC_OPENSEARCH_DASHBOARDS_URL` is set |
| 11 | **Alerts** | "Currently firing (down assets)" (empty when all green); link "Open Grafana → Alert rules" |
| 12 | **Reports** | Summary: Uptime %, Posture score (avg), Avg latency (ms), Assets (G/A/R); "Top incidents" if any red; **Download CSV** saves file |
| 13 | **Grafana** | Embedded posture dashboard (or open http://localhost:3001) |
| 14 | Sign out | Back to login |

---

## 3. API (PowerShell, no jq)

Run the script:

```powershell
.\scripts\test-api.ps1
```

You should see: token, posture summary (with `down_assets`), first asset, asset detail, and CSV saved as `posture.csv`.

**Reports summary:**

```powershell
$r = Invoke-RestMethod -Uri "http://localhost:8000/auth/login" -Method Post -Body @{username="admin";password="admin"} -ContentType "application/x-www-form-urlencoded"
$token = $r.access_token
Invoke-RestMethod -Uri "http://localhost:8000/posture/reports/summary?period=24h" -Headers @{Authorization="Bearer $token"} | ConvertTo-Json
```

Expect: `uptime_pct`, `posture_score_avg`, `avg_latency_ms`, `top_incidents`, `total_assets`, `green`, `amber`, `red`.

**Asset detail (with completeness/SLO):**

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/posture/juice-shop/detail?hours=24" -Headers @{Authorization="Bearer $token"} | ConvertTo-Json -Depth 5
```

Expect: `state`, `timeline`, `evidence`, `recommendations`, `expected_interval_sec`, `data_completeness` (checks, expected, label_24h, label_1h, pct_24h, pct_1h), `latency_slo_ms`, `latency_slo_ok`, `error_rate_24h`, `reason_display`.

---

## 4. Optional: force a failure (see red / down / recommendations)

1. **Stop Juice Shop:**  
   `docker compose stop juiceshop`

2. Wait for next ingestion cycle (e.g. 60s) or trigger your status build so `secplat-asset-status` has juice-shop as red.

3. **Refresh:**  
   - Overview: "Down assets" shows juice-shop.  
   - Alerts: juice-shop under "Currently firing".  
   - Asset detail for juice-shop: Status red, Reason e.g. `health_check_failed`, recommendations like "Asset is down — check connectivity...".

4. **Start Juice Shop again:**  
   `docker compose start juiceshop`  
   After ingestion runs again, status should go back to green.

---

## 5. Slack alert (POST /posture/alert/send)

Step-by-step with exact commands (PowerShell from repo root).

### 5.1 Start stack and get a token

```powershell
cd c:\Users\visha\Desktop\security-posture-platform
docker compose up -d
```

Wait until services are up (e.g. 1–2 min). Then get a JWT:

```powershell
$login = Invoke-RestMethod -Uri "http://localhost:8000/auth/login" -Method Post -Body @{ username = "admin"; password = "admin" } -ContentType "application/x-www-form-urlencoded"
$token = $login.access_token
```

### 5.2 Test without webhook (default)

Call the alert endpoint. With no `SLACK_WEBHOOK_URL` set, it should return `sent: false` and a message that the webhook is not configured (or "No down assets" if everything is green):

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/posture/alert/send" -Method Post -Headers @{ Authorization = "Bearer $token" } | ConvertTo-Json
```

**Expected:** `"sent": false`, `"down_assets": [...]`, `"message": "..."` (e.g. "No down assets" or "SLACK_WEBHOOK_URL not configured").

### 5.3 Test without down assets (webhook set)

1. Add a Slack Incoming Webhook (Slack app → Incoming Webhooks → Add to workspace → copy webhook URL).
2. In the repo root, add to `.env` (or set in shell):

   ```
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
   ```

3. Restart the API so it picks up the env var:

   ```powershell
   docker compose up -d api
   ```

4. Ensure all assets are green (e.g. don’t stop juiceshop). Call again:

   ```powershell
   $login = Invoke-RestMethod -Uri "http://localhost:8000/auth/login" -Method Post -Body @{ username = "admin"; password = "admin" } -ContentType "application/x-www-form-urlencoded"
   Invoke-RestMethod -Uri "http://localhost:8000/posture/alert/send" -Method Post -Headers @{ Authorization = "Bearer $login.access_token" } | ConvertTo-Json
   ```

**Expected:** `"sent": false`, `"down_assets": []`, `"message": "No down assets; no notification sent."` — no message in Slack.

### 5.4 Test with down assets + webhook (real Slack message)

1. Keep `SLACK_WEBHOOK_URL` in `.env` and API restarted (as in 5.3).
2. Create at least one down asset:

   ```powershell
   docker compose stop juiceshop
   ```

3. Wait for posture to turn red (ingestion runs every 60s; may take 1–2 min). Optional: check summary:

   ```powershell
   $t = (Invoke-RestMethod -Uri "http://localhost:8000/auth/login" -Method Post -Body @{ username = "admin"; password = "admin" } -ContentType "application/x-www-form-urlencoded").access_token
   Invoke-RestMethod -Uri "http://localhost:8000/posture/summary" -Headers @{ Authorization = "Bearer $t" } | ConvertTo-Json
   ```

   When `down_assets` contains `juice-shop`, continue.

4. Send the alert:

   ```powershell
   Invoke-RestMethod -Uri "http://localhost:8000/posture/alert/send" -Method Post -Headers @{ Authorization = "Bearer $t" } | ConvertTo-Json
   ```

**Expected:** `"sent": true`, `"down_assets": [ "juice-shop" ]`, and a message in the Slack channel: e.g. "SecPlat alert: 1 asset(s) down: juice-shop".

5. (Optional) Start juice-shop again:

   ```powershell
   docker compose start juiceshop
   ```

### 5.5 Test 401 without token

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/posture/alert/send" -Method Post
```

**Expected:** Error (401 Unauthorized). In PowerShell you may see an exception; the HTTP status should be 401.

### 5.6 Run full API test script (includes alert/send)

The script calls summary, list, detail, CSV, and **alert/send**:

```powershell
.\scripts\test-api.ps1
```

Check the "POSTURE ALERT SEND" block in the output for the same JSON as in 5.2.

---

## 6. Quick checklist

- [ ] Login works (admin/admin)
- [ ] Overview shows counts + down assets when any red
- [ ] Assets table has Criticality, Owner (Unassigned when empty), Env
- [ ] Asset detail: Expected interval, Data completeness (24h + 1h), Latency SLO, Error rate (24h)
- [ ] Asset detail: Reason shows – when green; Copy JSON works
- [ ] Timeline: anomaly highlight + "spike" badge for latency > 200ms
- [ ] Alerts: firing list from API; Grafana link
- [ ] Reports: summary cards + top incidents + CSV download
- [ ] API: `.\scripts\test-api.ps1` and reports/summary, asset detail return expected fields
- [ ] Alert: `POST /posture/alert/send` returns `sent`/`down_assets`/`message`; with webhook + down asset, Slack receives message

If any step fails, check `docker logs secplat-api --tail 50` and browser devtools (Network tab) for errors.
