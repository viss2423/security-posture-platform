# Incident Postmortem Evidence

This directory tracks Sev1/Sev2 platform incident postmortems.

## Requirements

- Every closed `sev1`/`sev2` incident must have one postmortem markdown file.
- Filename format:
  - `YYYY-MM-DD-sev1-<slug>.md`
  - `YYYY-MM-DD-sev2-<slug>.md`
- Use `template.md` as the source template.
- Include at least one prevention action item.

## Validation

- Script: `python services/api/scripts/check_postmortem_evidence.py`
- CI runs this check in the supply-chain workflow.
