"""
Compliance evidence router.

Aggregates posture connector findings and maps them to SOC 2, ISO 27001, and
CIS controls, producing pass/fail evidence reports.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.request_context import current_tenant_id
from app.routers.auth import require_auth
from app.settings import settings

router = APIRouter(prefix="/compliance", tags=["compliance"])

SOURCES = ("github_posture", "aws_iam_posture")


@dataclass
class Soc2Control:
    control_id: str
    name: str
    description: str
    check_ids: list[str]


SOC2_CONTROLS: list[Soc2Control] = [
    Soc2Control(
        control_id="CC6.1",
        name="Logical & Physical Access Controls",
        description=(
            "Protect against unauthorised access. Covers 2FA and "
            "secret scanning for leaked credentials."
        ),
        check_ids=[
            "org_2fa",
            "secret_scanning",
            "aws_root_mfa",
            "aws_password_policy",
            "aws_admin_policy",
        ],
    ),
    Soc2Control(
        control_id="CC7.1",
        name="System Operations — Vulnerability Detection",
        description=(
            "Detect vulnerabilities and apply remediation. "
            "Covers Dependabot vulnerability alerts."
        ),
        check_ids=["dependabot_alerts"],
    ),
    Soc2Control(
        control_id="CC8.1",
        name="Change Management",
        description=(
            "Authorise and approve changes to infrastructure and code. "
            "Covers branch protection requiring PR review before merge."
        ),
        check_ids=["branch_protection"],
    ),
]


@dataclass
class ComplianceControl:
    framework: str
    control_id: str
    name: str
    description: str
    check_ids: list[str]


CONTROL_CATALOG: list[ComplianceControl] = [
    ComplianceControl(
        framework="SOC 2",
        control_id="CC6.1",
        name="Logical & Physical Access Controls",
        description=(
            "Protect against unauthorised access. Covers 2FA and "
            "secret scanning for leaked credentials."
        ),
        check_ids=[
            "org_2fa",
            "secret_scanning",
            "aws_root_mfa",
            "aws_password_policy",
            "aws_admin_policy",
        ],
    ),
    ComplianceControl(
        framework="SOC 2",
        control_id="CC6.6",
        name="Logical Access Monitoring",
        description=(
            "Restrict and monitor logical access to sensitive assets. "
            "Covers public repository exposure and secret scanning."
        ),
        check_ids=["public_repo", "secret_scanning", "aws_stale_access_keys", "aws_unused_user"],
    ),
    ComplianceControl(
        framework="SOC 2",
        control_id="CC7.1",
        name="System Operations - Vulnerability Detection",
        description=(
            "Detect vulnerabilities and apply remediation. "
            "Covers Dependabot vulnerability alerts."
        ),
        check_ids=["dependabot_alerts"],
    ),
    ComplianceControl(
        framework="SOC 2",
        control_id="CC8.1",
        name="Change Management",
        description=(
            "Authorise and approve changes to infrastructure and code. "
            "Covers branch protection requiring PR review before merge."
        ),
        check_ids=["branch_protection"],
    ),
    ComplianceControl(
        framework="ISO 27001",
        control_id="A.5.15",
        name="Access Control",
        description=(
            "Access to information and associated assets is controlled. "
            "Covers organisation-level 2FA and repository exposure."
        ),
        check_ids=[
            "org_2fa",
            "public_repo",
            "aws_root_mfa",
            "aws_password_policy",
            "aws_admin_policy",
            "aws_stale_access_keys",
            "aws_unused_user",
        ],
    ),
    ComplianceControl(
        framework="ISO 27001",
        control_id="A.8.8",
        name="Management of Technical Vulnerabilities",
        description=(
            "Information about technical vulnerabilities is obtained, "
            "evaluated, and acted on. Covers Dependabot alerts."
        ),
        check_ids=["dependabot_alerts"],
    ),
    ComplianceControl(
        framework="ISO 27001",
        control_id="A.8.9",
        name="Configuration Management",
        description=(
            "Configurations are established, implemented, monitored, "
            "and reviewed. Covers branch protection and repository "
            "security features."
        ),
        check_ids=["branch_protection", "secret_scanning"],
    ),
    ComplianceControl(
        framework="ISO 27001",
        control_id="A.8.12",
        name="Data Leakage Prevention",
        description=(
            "Data leakage prevention measures are applied to systems and "
            "networks. Covers secret scanning and public repositories."
        ),
        check_ids=["secret_scanning", "public_repo"],
    ),
    ComplianceControl(
        framework="CIS",
        control_id="CIS 5.4",
        name="Restrict Administrator Privileges with MFA",
        description=(
            "Require multi-factor authentication for privileged and remote "
            "access. Covers GitHub organisation 2FA enforcement."
        ),
        check_ids=["org_2fa", "aws_root_mfa", "aws_password_policy"],
    ),
    ComplianceControl(
        framework="CIS",
        control_id="CIS 4.1",
        name="Secure Configuration of Enterprise Assets",
        description=(
            "Establish and maintain secure configuration. Covers branch "
            "protection, secret scanning, and public repository exposure."
        ),
        check_ids=["branch_protection", "secret_scanning", "public_repo", "aws_admin_policy"],
    ),
    ComplianceControl(
        framework="CIS",
        control_id="CIS 7.1",
        name="Vulnerability Management Process",
        description=(
            "Establish and maintain a vulnerability management process. "
            "Covers Dependabot vulnerability alerts."
        ),
        check_ids=["dependabot_alerts"],
    ),
    ComplianceControl(
        framework="CIS",
        control_id="CIS 16.3",
        name="Secure Application Development",
        description=(
            "Protect application code changes through review and controlled "
            "merge paths. Covers default branch protection."
        ),
        check_ids=["branch_protection"],
    ),
]

SOC2_CONTROLS = [c for c in CONTROL_CATALOG if c.framework == "SOC 2"]


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------


def _multi_tenant_mode() -> bool:
    raw = getattr(settings, "TENANCY_MODE", "single") or "single"
    return raw.strip().lower() == "multi"


def _has_posture_scan_run(db: Session) -> bool:
    """True if at least one posture connector job has completed *for this tenant*."""
    org_filter = ""
    params: dict = {"job_types": list(SOURCES)}
    if _multi_tenant_mode():
        org_filter = "AND org_id = :org_id"
        params["org_id"] = current_tenant_id()
    row = db.execute(
        text(
            f"SELECT 1 FROM scan_jobs"
            f" WHERE job_type = ANY(:job_types) AND status = 'done' {org_filter}"
            f" LIMIT 1"
        ),
        params,
    ).fetchone()
    return row is not None


def _fetch_posture_findings(db: Session) -> list[dict[str, Any]]:
    """Return ALL posture connector findings - open and remediated.

    Open findings drive FAIL.  Remediated findings serve as PASS evidence
    (they prove a previously-failing check was fixed).  The connector
    only emits a finding record when a check fails, so *absence* of an open
    finding for a check that was previously scanned means the check is now clean.
    """
    org_filter = ""
    params: dict = {}
    if _multi_tenant_mode():
        org_filter = "AND a.org_id = :org_id"
        params["org_id"] = current_tenant_id()

    q = text(
        f"""
        SELECT
            f.finding_id, f.finding_key, f.title, f.severity,
            COALESCE(f.status, 'open') AS status,
            f.evidence, f.remediation, f.source, f.scanner_metadata_json,
            f.first_seen, f.last_seen,
            a.asset_key, a.name AS asset_name
        FROM findings f
        JOIN assets a ON a.asset_id = f.asset_id
        WHERE f.source = ANY(:sources)
          {org_filter}
        ORDER BY f.last_seen DESC NULLS LAST
        """
    )
    params["sources"] = list(SOURCES)
    rows = db.execute(q, params).mappings().all()
    return [dict(r) for r in rows]


def _parse_check(finding: dict) -> str | None:
    meta = finding.get("scanner_metadata_json")
    if meta is None:
        return None
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except (json.JSONDecodeError, TypeError):
            return None
    check = (meta or {}).get("check")
    return str(check) if check else None


def _scope_from_meta(meta: Any) -> str | None:
    if meta is None:
        return None
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except (json.JSONDecodeError, TypeError):
            return None
    data = meta or {}
    return data.get("repo") or data.get("user") or data.get("region")


def _iso(val: Any) -> str | None:
    if val is None:
        return None
    if hasattr(val, "isoformat"):
        return val.isoformat()
    return str(val)


# ---------------------------------------------------------------------------
# Evidence report builder
# ---------------------------------------------------------------------------


def _build_evidence_report(db: Session) -> dict:
    """Query findings and assemble the compliance evidence structure.

    Key insight: the GitHub connector only emits a finding when a check
    *fails* (2FA off, branch unprotected, etc.).  A check that passes
    produces no finding at all.  So we cannot infer "pass" from the
    absence of a finding — we need a scan-ran signal to distinguish
    "scanned + clean" from "never scanned".

    Logic:
      - No github_posture job ever completed  →  not_applicable
      - Scan ran + any open finding exists     →  fail
      - Scan ran + zero open findings          →  pass
        (remediated findings are included as evidence of prior fixes)
    """
    scan_ran = _has_posture_scan_run(db)
    findings = _fetch_posture_findings(db)

    by_check: dict[str, list[dict]] = {}
    for f in findings:
        check = _parse_check(f)
        if check:
            by_check.setdefault(check, []).append(f)

    controls: list[dict] = []
    total_pass = 0
    total_fail = 0

    for ctrl in CONTROL_CATALOG:
        evidence_items: list[dict] = []
        for cid in ctrl.check_ids:
            items = by_check.get(cid, [])
            evidence_items.extend(items)

        # Anything not remediated counts as failing (open, in_progress,
        # accepted_risk are all unresolved from a compliance standpoint).
        open_items = [e for e in evidence_items if e.get("status") != "remediated"]
        remediated_items = [e for e in evidence_items if e.get("status") == "remediated"]

        if not scan_ran:
            status = "not_applicable"
        elif open_items:
            status = "fail"
            total_fail += 1
        else:
            status = "pass"
            total_pass += 1

        # Evidence: for FAIL show open items; for PASS show remediated
        # items as proof of prior fixes; for N/A show nothing.
        display_items = open_items if status == "fail" else remediated_items

        controls.append(
            {
                "framework": ctrl.framework,
                "control_id": ctrl.control_id,
                "name": ctrl.name,
                "description": ctrl.description,
                "status": status,
                "total_checks": len(evidence_items),
                "open_count": len(open_items),
                "remediated_count": len(remediated_items),
                "evidence": [
                    {
                        "finding_id": e["finding_id"],
                        "title": e["title"],
                        "severity": e["severity"],
                        "status": e.get("status", "open"),
                        "evidence": e.get("evidence"),
                        "remediation": e.get("remediation"),
                        "repo": _scope_from_meta(e.get("scanner_metadata_json")),
                        "source": e.get("source"),
                        "check_type": _parse_check(e),
                        "first_seen": _iso(e.get("first_seen")),
                        "last_seen": _iso(e.get("last_seen")),
                    }
                    for e in display_items
                ],
            }
        )

    total_controls = len(controls)
    applicable = total_controls - (  # controls where a scan has run
        sum(1 for c in controls if c["status"] == "not_applicable")
    )
    score_pct = round((total_pass / max(applicable, 1)) * 100) if applicable > 0 else None

    # open_findings = anything not remediated (open, in_progress, accepted_risk)
    active_all = [f for f in findings if f.get("status") != "remediated"]
    remediated_all = [f for f in findings if f.get("status") == "remediated"]

    return {
        "report_id": str(uuid.uuid4())[:8],
        "generated_at": datetime.now(UTC).isoformat(),
        "source": ",".join(SOURCES),
        "sources": list(SOURCES),
        "scan_ran": scan_ran,
        "frameworks": sorted({c["framework"] for c in controls}),
        "scope": {
            "asset_count": len({f.get("asset_key") for f in findings}),
            "total_findings": len(findings),
            "open_findings": len(active_all),
            "remediated_findings": len(remediated_all),
        },
        "score": {
            "pass": total_pass,
            "fail": total_fail,
            "not_applicable": total_controls - total_pass - total_fail,
            "percentage": score_pct,
        },
        "controls": controls,
    }


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------


@router.get("/soc2/evidence")
def get_soc2_evidence(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Return compliance evidence report as structured JSON."""
    return _build_evidence_report(db)


@router.get("/evidence")
def get_compliance_evidence(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Return mapped compliance evidence report as structured JSON."""
    return _build_evidence_report(db)


@router.get("/soc2/evidence.pdf", response_class=Response)
def download_soc2_evidence_pdf(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Download compliance evidence report as PDF."""
    return download_compliance_evidence_pdf(db, _user)


@router.get("/evidence.pdf", response_class=Response)
def download_compliance_evidence_pdf(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Download compliance evidence report as PDF."""
    report = _build_evidence_report(db)
    pdf_bytes = _render_soc2_pdf(report)
    org = getattr(settings, "REPORT_ORG_NAME", "SecPlat") or "SecPlat"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                "attachment; filename=" f"{org.lower()}-compliance-evidence-report.pdf"
            )
        },
    )


@router.get("/soc2/evidence.csv", response_class=Response)
def download_soc2_evidence_csv(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Download compliance evidence report as CSV."""
    return download_compliance_evidence_csv(db, _user)


@router.get("/evidence.csv", response_class=Response)
def download_compliance_evidence_csv(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Download compliance evidence report as CSV."""
    report = _build_evidence_report(db)
    csv_bytes = _render_evidence_csv(report)
    org = getattr(settings, "REPORT_ORG_NAME", "SecPlat") or "SecPlat"
    return Response(
        content=csv_bytes,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                "attachment; filename=" f"{org.lower()}-compliance-evidence-report.csv"
            )
        },
    )


# ---------------------------------------------------------------------------
# Export Rendering
# ---------------------------------------------------------------------------


def _render_evidence_csv(report: dict) -> bytes:
    """Render mapped compliance evidence as UTF-8 CSV."""
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=[
            "report_id",
            "generated_at",
            "framework",
            "control_id",
            "control_name",
            "control_status",
            "source",
            "check_type",
            "finding_id",
            "finding_title",
            "severity",
            "finding_status",
            "repo",
            "first_seen",
            "last_seen",
            "evidence",
            "remediation",
        ],
    )
    writer.writeheader()

    for ctrl in report["controls"]:
        evidence = ctrl.get("evidence") or [None]
        for ev in evidence:
            writer.writerow(
                {
                    "report_id": report["report_id"],
                    "generated_at": report["generated_at"],
                    "framework": ctrl.get("framework"),
                    "control_id": ctrl.get("control_id"),
                    "control_name": ctrl.get("name"),
                    "control_status": ctrl.get("status"),
                    "source": (ev or {}).get("source"),
                    "check_type": (ev or {}).get("check_type"),
                    "finding_id": (ev or {}).get("finding_id"),
                    "finding_title": (ev or {}).get("title"),
                    "severity": (ev or {}).get("severity"),
                    "finding_status": (ev or {}).get("status"),
                    "repo": (ev or {}).get("repo"),
                    "first_seen": (ev or {}).get("first_seen"),
                    "last_seen": (ev or {}).get("last_seen"),
                    "evidence": (ev or {}).get("evidence"),
                    "remediation": (ev or {}).get("remediation"),
                }
            )

    return buf.getvalue().encode("utf-8")


def _render_soc2_pdf(report: dict) -> bytes:
    """Render compliance evidence as a multi-page PDF using reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    body_style = styles["BodyText"]
    body_style.fontSize = 10
    body_style.leading = 14

    h2 = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontSize=14,
        spaceAfter=10,
        spaceBefore=18,
        textColor=colors.HexColor("#1e293b"),
    )

    story: list = []

    # Title
    org = getattr(settings, "REPORT_ORG_NAME", "SecPlat") or "SecPlat"
    story.append(
        Paragraph(
            f"<b>{org}</b> - Compliance Evidence Report",
            ParagraphStyle(
                "Title",
                parent=styles["Title"],
                fontSize=20,
                textColor=colors.HexColor("#0f172a"),
                spaceAfter=4,
            ),
        )
    )
    story.append(
        Paragraph(
            f"Report ID: {report['report_id']}  |  "
            f"Generated: {report['generated_at'][:19].replace('T', ' ')} UTC  |  "
            f"Sources: {', '.join(report.get('sources') or [report.get('source', 'posture')])}",
            ParagraphStyle(
                "Subtitle",
                parent=body_style,
                fontSize=8,
                textColor=colors.HexColor("#64748b"),
                spaceAfter=18,
            ),
        )
    )

    # Score
    score = report["score"]
    pct = score["percentage"]
    pct_str = f"{pct}%" if pct is not None else "N/A"
    box_color = colors.HexColor("#16a34a")
    if pct is not None and pct < 80:
        box_color = colors.HexColor("#ea580c")
    if pct is not None and pct < 50:
        box_color = colors.HexColor("#dc2626")

    score_style = ParagraphStyle(
        "ScoreBox", parent=body_style, fontSize=10, textColor=colors.white, alignment=1
    )
    score_table = Table(
        [[Paragraph(f"<b>Control Pass Rate: {pct_str}</b>", score_style)]],
        colWidths=[6.5 * inch],
        rowHeights=[0.45 * inch],
    )
    score_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), box_color),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(score_table)
    story.append(Spacer(1, 8))

    # Scan-status banner
    if not report.get("scan_ran"):
        story.append(
            Paragraph(
                "<i>No posture connector scan has completed yet. "
                "Run a scan to populate control evidence.</i>",
                ParagraphStyle(
                    "Warn",
                    parent=body_style,
                    fontSize=9,
                    textColor=colors.HexColor("#ea580c"),
                    spaceAfter=4,
                ),
            )
        )
        story.append(Spacer(1, 4))

    summary = (
        f"Pass: {score['pass']}  |  Fail: {score['fail']}  |  "
        f"N/A: {score['not_applicable']}  |  "
        f"Assets: {report['scope']['asset_count']}  |  "
        f"Open: {report['scope']['open_findings']}  |  "
        f"Remediated: {report['scope']['remediated_findings']}"
    )
    story.append(Paragraph(summary, body_style))
    story.append(Spacer(1, 18))

    # Controls
    for ctrl in report["controls"]:
        status = ctrl["status"]
        status_color = {"pass": "#16a34a", "fail": "#dc2626"}.get(status, "#64748b")
        status_label = {"pass": "PASS", "fail": "FAIL"}.get(status, "N/A")

        story.append(
            Paragraph(
                f"{ctrl.get('framework', 'Compliance')} {ctrl['control_id']} - "
                f"{ctrl['name']}  "
                f'<font color="{status_color}"><b>[{status_label}]</b></font>',
                h2,
            )
        )
        story.append(Paragraph(ctrl["description"], body_style))

        oc = ctrl.get("open_count", 0)
        rc = ctrl.get("remediated_count", 0)
        check_detail = ""
        if oc or rc:
            parts = []
            if oc:
                parts.append(f"{oc} open")
            if rc:
                parts.append(f"{rc} remediated")
            check_detail = " | ".join(parts)
        if check_detail:
            story.append(
                Paragraph(
                    f"<i>{check_detail}</i>",
                    ParagraphStyle(
                        "CheckCount",
                        parent=body_style,
                        fontSize=9,
                        textColor=colors.HexColor("#64748b"),
                        spaceBefore=2,
                        spaceAfter=4,
                    ),
                )
            )
        story.append(Spacer(1, 4))

        if ctrl["evidence"]:
            headers = ["Title", "Severity", "Status", "Repo"]
            rows = [headers]
            ev_style = ParagraphStyle("EvCell", parent=body_style, fontSize=8, leading=10)
            for ev in ctrl["evidence"]:
                rows.append(
                    [
                        Paragraph(ev["title"] or "-", ev_style),
                        (ev["severity"] or "-").upper(),
                        (ev.get("status", "open") or "open").upper(),
                        ev["repo"] or "-",
                    ]
                )
            tbl = Table(rows, colWidths=[2.8 * inch, 0.7 * inch, 0.8 * inch, 1.9 * inch])
            tbl.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            story.append(tbl)
        elif ctrl["status"] == "pass":
            story.append(Paragraph("<i>No findings - all checks are passing.</i>", body_style))
        else:
            story.append(
                Paragraph(
                    "<i>No evidence - control is not applicable (no scan has run).</i>", body_style
                )
            )
        story.append(Spacer(1, 14))

    # Footer
    story.append(Spacer(1, 20))
    story.append(
        Paragraph(
            "<i>Generated from live posture connector findings mapped to "
            "SOC 2, ISO 27001, and CIS controls.</i>",
            ParagraphStyle(
                "Footer", parent=body_style, fontSize=7, textColor=colors.HexColor("#94a3b8")
            ),
        )
    )

    doc.build(story)
    return buf.getvalue()
