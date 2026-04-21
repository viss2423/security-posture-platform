# Incident Severity and Escalation (Phase 6)

## Severity criteria

- `Sev1`: platform unavailable, cross-tenant exposure risk, or active data-loss scenario.
- `Sev2`: partial outage, sustained ingestion delay, or critical workflow blocked.
- `Sev3`: limited scope defect, non-critical latency regression, or support request.

## Escalation flow

1. Triage and classify severity within 15 minutes.
2. Assign incident commander for Sev1/Sev2.
3. Open dedicated incident channel and timeline log.
4. Trigger customer communications per SLA.
5. Close with postmortem containing at least one prevention action item.

Postmortem evidence is stored in `docs/operations/postmortems/` and validated with:

- `python services/api/scripts/check_postmortem_evidence.py`
