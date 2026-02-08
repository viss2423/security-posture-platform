# Testing the SecPlat Grafana dashboard changes

## 1. Apply changes

```powershell
# From repo root
docker compose restart grafana
```

Wait ~30s for Grafana to come up. Open http://localhost:3001 (or your `GRAFANA_PORT`), log in.

---

## 2. Dashboard loads and layout

- Go to **Dashboards → SecPlat → SecPlat - Asset Posture**.
- **Top row**: Healthy 4, Stale 0, Overall 100, Green 4, Amber 0, Red 0, Unknown 0.
- **Table**: Asset Posture (Current) shows asset_key, name, type, environment, posture_state, posture_score, last_seen.
- **Bottom**: Row “Posture over time & triage” with two panels:
  - **Overall Posture Score (time series)** – line chart.
  - **Staleness & last status change (triage)** – table sorted by staleness.

If any panel shows “No data”, set time range to **Last 15 minutes** or **Last 1 hour** and refresh.

---

## 3. Template variable `$asset`

- At the top of the dashboard you should see a dropdown **asset** (default: secplat-api).
- Change it to **verify-web**, **example-com**, **juice-shop**.
- Scroll down to **Juice Shop Reachability**, **API Latency (ms)**, **Total Events**, **API Health Pings / Minute**, **API Status**.
- Change `asset` and refresh: those panels should update (or show no data for an asset that has no events in the time range).  
  If they stay empty for all assets, check that the **OpenSearch** datasource uses index `secplat-events` and that health ingestion has run (see step 5).

---

## 4. Alerts (Red and Stale)

The two alert rules are **provisioned** from `infra/grafana/provisioning/alerting/secplat-alerts.yaml` and should appear under **Alerting → Alert rules** after Grafana starts (folder **General**, group **SecPlat Posture**).

- **Any asset red**: fires when Red count > 0 for 1m (linked to Red panel).
- **Stale assets present**: fires when Stale count > 0 for 2m (linked to Stale panel).

If you still see “You haven’t created any alert rules yet”:

1. Check Grafana logs for provisioning errors:  
   `docker compose logs grafana 2>&1 | findstr -i alert`
2. Ensure the **OpenSearch (asset-status)** datasource uid is `P3DECE5F6851F5FA5` (see `infra/grafana/provisioning/datasources/opensearch-asset-status.yaml`).
3. **Create from the UI once**: open the dashboard → click the **Red** panel title → **Alert** → **Create alert rule from this panel** → set “Alert when” to “last value of A is above 0”, **For** 1m → **Save**. Repeat for the **Stale Assets** panel (refId `secplat-asset-status`, above 0, **For** 2m). Then export the rule group (Alert rules → SecPlat Posture → Export) and replace the content of `secplat-alerts.yaml` with the export so future restarts keep the rules.

**Test Red:**

```powershell
docker compose stop api
```

Wait 2–3 minutes (ingestion runs every 60s). Refresh dashboard: one asset should go red, **Red** panel should show 1. In Grafana: **Alerting → Alert rules** and confirm the rule “Any asset red” exists and fires (or “Creating…”). Restore:

```powershell
docker compose start api
```

**Test Stale (optional):** Stale = no recent health event. Harder to trigger quickly; you can leave it and just confirm the rule exists under Alerting → Alert rules.

To get notifications, add a **Contact point** (Alerting → Contact points), e.g. Email or “Test” (logs only), and attach it to the default notification policy or to these rules.

---

## 5. Events panels (API Latency, Health Pings, etc.)

Those panels use the **OpenSearch** datasource with index `secplat-events`. If they show “No data”:

- Ensure **ingestion** is running: `docker compose ps` → `secplat-ingestion` up.
- Wait at least one ingestion interval (60s) after stack start.
- In Grafana: **Connections → Data sources → OpenSearch** (uid P9744FCCEAAFBD98F): confirm **Index name** = `secplat-events`.
- Set dashboard time range to **Last 1 hour** and pick **asset** = secplat-api or juice-shop.

---

## 6. Quick checklist

| What to check | How |
|---------------|-----|
| Green/Amber/Red show 4 / 0 / 0 (not 181 or “No data”) | Top row, time range Last 15m |
| Table has posture_state, posture_score, last_seen | Asset Posture (Current) |
| Default time range | Opens as “Last 15 minutes” |
| `asset` dropdown | Top of dashboard, 4 options |
| Posture score time series | Bottom row, left panel |
| Staleness triage table | Bottom row, right panel, sorted by staleness |
| Red alert fires when API down | Stop API, wait 2–3 min, check Red panel and Alerting |

---

## 7. Reset after tests

```powershell
docker compose start api    # if you stopped it
docker compose ps          # all services running
```

Then refresh the dashboard; posture should return to all green.
