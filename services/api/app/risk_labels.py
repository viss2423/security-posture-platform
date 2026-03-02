"""Shared label definitions for finding risk model training."""

VALID_RISK_LABELS = ("incident_worthy", "benign")
POSITIVE_RISK_LABELS = {"incident_worthy"}
VALID_RISK_LABEL_SOURCES = ("analyst", "incident_linked", "accepted_risk", "imported")


def label_to_target(label: str) -> int:
    return 1 if label in POSITIVE_RISK_LABELS else 0
