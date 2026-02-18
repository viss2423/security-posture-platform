# secplat-queue (Python library)

Minimal Redis Streams client for SecPlat. Used by API (publish), scan-workers, deriver, notifier (consume).

**Streams:** `secplat.jobs.scan`, `secplat.jobs.derive`, `secplat.events.notify`

**Usage:**

- `publish(stream, message)` — add message to stream
- `consume(stream, group, consumer, handler)` — read from stream with consumer group; call handler(msg); retry with backoff; DLQ on max retries

See Phase 1 in [docs/SECPLAT-CORPORATE-ROADMAP.md](../../docs/SECPLAT-CORPORATE-ROADMAP.md).
