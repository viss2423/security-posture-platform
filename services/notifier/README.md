# secplat-notifier (Notifications Service)

**Phase 2.3.** Move Slack/Twilio out of the API.

- Consumes `secplat.events.notify` (Redis Stream) with consumer group `notifiers`
- On `type=down_assets` messages: sends Slack (webhook) and/or WhatsApp (Twilio)
- Env: `REDIS_URL`, `SLACK_WEBHOOK_URL`, `TWILIO_*`, `WHATSAPP_ALERT_TO` (same as API)
- API: when `REDIS_URL` is set, `POST /posture/alert/send` publishes to the stream and returns `queued`; notifier sends. Without Redis, API calls Slack/Twilio directly (legacy).

See [docs/SECPLAT-CORPORATE-ROADMAP.md](../../docs/SECPLAT-CORPORATE-ROADMAP.md) and [docs/architecture.md](../../docs/architecture.md).
