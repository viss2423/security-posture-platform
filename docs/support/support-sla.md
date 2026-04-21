# Support SLA (Phase 6)

## Severity levels

- `Sev1`: customer-impacting outage or data loss risk
- `Sev2`: major feature degradation with workaround limitations
- `Sev3`: non-critical defect or operational question

## Response targets

| Severity | Initial response | Update cadence |
| --- | --- | --- |
| Sev1 | 30 minutes | Every 60 minutes |
| Sev2 | 120 minutes | Every 4 hours |
| Sev3 | 8 business hours | Daily (business days) |

## Escalation

1. On-call engineer acknowledges ticket.
2. Incident commander assigned for Sev1/Sev2.
3. Post-incident review required for Sev1 and repeating Sev2 incidents.
