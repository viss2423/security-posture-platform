"""
SOC 2 compliance evidence router.

Aggregates github_posture findings and maps them to SOC 2 Trust Services
Criteria controls, producing pass/fail evidence reports.
"""

from __future__ import annotations

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

SOURCE = "github_posture"


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
        check_ids=["org_2fa", "secret_scanning"],
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


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------


def _multi_tenant_mode() -> bool:
    raw = getattr(settings, "TENANCY_MODE", "single") or "single"
    return raw.strip().lower() == "multi"


def _has_github_scan_run(db: Session) -> bool:
    """True if at least one github_posture job has completed *for this tenant*."""
    org_filter = ""
    params: dict = {"job_type": SOURCE}
    if _multi_tenant_mode():
        org_filter = "AND org_id = :org_id"
        params["org_id"] = current_tenant_id()
    row = db.execute(
        text(
            f"SELECT 1 FROM scan_jobs"
            f" WHERE job_type = :job_type AND status = 'done' {org_filter}"
            f" LIMIT 1"
        ),
        params,
    ).fetchone()
    return row is not None


def _fetch_github_findings(db: Session) -> list[dict[str, Any]]:
    """Return ALL github_posture findings — open and remediated.

    Open findings drive FAIL.  Remediated findings serve as PASS evidence
    (they prove a previously-failing check was fixed).  The connector
    only emits a finding record when a check fails (github_connector.py:218+),
    so *absence* of an open finding for a check that was previously scanned
    means the check is now clean.
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
            f.evidence, f.remediation, f.scanner_metadata_json,
            f.first_seen, f.last_seen,
            a.asset_key, a.name AS asset_name
        FROM findings f
        JOIN assets a ON a.asset_id = f.asset_id
        WHERE f.source = :source
          {org_filter}
        ORDER BY f.last_seen DESC NULLS LAST
        """
    )
    params["source"] = SOURCE
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


def _repo_from_meta(meta: Any) -> str | None:
    if meta is None:
        return None
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except (json.JSONDecodeError, TypeError):
            return None
    return (meta or {}).get("repo")


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
    """Query findings and assemble the SOC 2 evidence structure.

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
    scan_ran = _has_github_scan_run(db)
    findings = _fetch_github_findings(db)

    by_check: dict[str, list[dict]] = {}
    for f in findings:
        check = _parse_check(f)
        if check:
            by_check.setdefault(check, []).append(f)

    controls: list[dict] = []
    total_pass = 0
    total_fail = 0

    for ctrl in SOC2_CONTROLS:
        evidence_items: list[dict] = []
        for cid in ctrl.check_ids:
            items = by_check.get(cid, [])
            evidence_items.extend(items)

        # Anything not remediated counts as failing (open, in_progress,
        # accepted_risk are all unresolved from a compliance standpoint).
        open_items = [e for e in evidence_items
                      if e.get("status") != "remediated"]
        remediated_items = [e for e in evidence_items
                            if e.get("status") == "remediated"]

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

        controls.append({
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
                    "repo": _repo_from_meta(
                        e.get("scanner_metadata_json")),
                    "check_type": _parse_check(e),
                    "first_seen": _iso(e.get("first_seen")),
                    "last_seen": _iso(e.get("last_seen")),
                }
                for e in display_items
            ],
        })

    total_controls = len(controls)
    applicable = total_controls - (  # controls where a scan has run
        sum(1 for c in controls if c["status"] == "not_applicable"))
    score_pct = (
        round((total_pass / max(applicable, 1)) * 100)
        if applicable > 0 else None
    )

    # open_findings = anything not remediated (open, in_progress, accepted_risk)
    active_all = [f for f in findings if f.get("status") != "remediated"]
    remediated_all = [f for f in findings
                      if f.get("status") == "remediated"]

    return {
        "report_id": str(uuid.uuid4())[:8],
        "generated_at": datetime.now(UTC).isoformat(),
        "source": SOURCE,
        "scan_ran": scan_ran,
        "scope": {
            "asset_count": len({
                f.get("asset_key") for f in findings
            }),
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
    """Return SOC 2 evidence report as structured JSON."""
    return _build_evidence_report(db)


@router.get("/soc2/evidence.pdf", response_class=Response)
def download_soc2_evidence_pdf(
    db: Session = Depends(get_db),
    _user: str = Depends(require_auth),
):
    """Download SOC 2 compliance evidence report as PDF."""
    report = _build_evidence_report(db)
    pdf_bytes = _render_soc2_pdf(report)
    org = getattr(settings, "REPORT_ORG_NAME", "SecPlat") or "SecPlat"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                "attachment; filename="
                f"{org.lower()}-soc2-evidence-report.pdf"
            )
        },
    )



# ---------------------------------------------------------------------------
# PDF Rendering
# ---------------------------------------------------------------------------


def _render_soc2_pdf(report: dict) -> bytes:
    """Render SOC 2 evidence as a multi-page PDF using reportlab."""
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
        buf, pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    body_style = styles["BodyText"]
    body_style.fontSize = 10
    body_style.leading = 14

    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14,
                        spaceAfter=10, spaceBefore=18,
                        textColor=colors.HexColor("#1e293b"))

    story: list = []

    # Title
    org = getattr(settings, "REPORT_ORG_NAME", "SecPlat") or "SecPlat"
    story.append(Paragraph(
        f"<b>{org}</b> — SOC 2 Compliance Evidence Report",
        ParagraphStyle("Title", parent=styles["Title"], fontSize=20,
                       textColor=colors.HexColor("#0f172a"), spaceAfter=4)))
    story.append(Paragraph(
        f"Report ID: {report['report_id']}  |  "
        f"Generated: {report['generated_at'][:19].replace('T', ' ')} UTC  |  "
        f"Source: GitHub Posture Connector",
        ParagraphStyle("Subtitle", parent=body_style, fontSize=8,
                       textColor=colors.HexColor("#64748b"), spaceAfter=18)))

    # Score
    score = report["score"]
    pct = score["percentage"]
    pct_str = f"{pct}%" if pct is not None else "N/A"
    box_color = colors.HexColor("#16a34a")
    if pct is not None and pct < 80:
        box_color = colors.HexColor("#ea580c")
    if pct is not None and pct < 50:
        box_color = colors.HexColor("#dc2626")

    score_style = ParagraphStyle("ScoreBox", parent=body_style, fontSize=10,
                                 textColor=colors.white, alignment=1)
    score_table = Table(
        [[Paragraph(f"<b>Control Pass Rate: {pct_str}</b>", score_style)]],
        colWidths=[6.5 * inch], rowHeights=[0.45 * inch])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), box_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 8))

    # Scan-status banner
    if not report.get("scan_ran"):
        story.append(Paragraph(
            "<i>⚠ No GitHub posture scan has completed yet.  "
            "Run a scan to populate control evidence.</i>",
            ParagraphStyle("Warn", parent=body_style, fontSize=9,
                          textColor=colors.HexColor("#ea580c"),
                          spaceAfter=4)))
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
        status_color = {"pass": "#16a34a", "fail": "#dc2626"}.get(
            status, "#64748b")
        status_label = {"pass": "PASS", "fail": "FAIL"}.get(status, "N/A")

        story.append(Paragraph(
            f"{ctrl['control_id']} — {ctrl['name']}  "
            f'<font color="{status_color}"><b>[{status_label}]</b></font>',
            h2))
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
            check_detail = " · ".join(parts)
        if check_detail:
            story.append(Paragraph(
                f"<i>{check_detail}</i>",
                ParagraphStyle("CheckCount", parent=body_style, fontSize=9,
                              textColor=colors.HexColor("#64748b"),
                              spaceBefore=2, spaceAfter=4)))
        story.append(Spacer(1, 4))

        if ctrl["evidence"]:
            headers = ["Title", "Severity", "Status", "Repo"]
            rows = [headers]
            ev_style = ParagraphStyle("EvCell", parent=body_style,
                                      fontSize=8, leading=10)
            for ev in ctrl["evidence"]:
                rows.append([
                    Paragraph(ev["title"] or "—", ev_style),
                    (ev["severity"] or "—").upper(),
                    (ev.get("status", "open") or "open").upper(),
                    ev["repo"] or "—",
                ])
            tbl = Table(rows, colWidths=[2.8 * inch, 0.7 * inch, 0.8 * inch, 1.9 * inch])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0),
                 colors.HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5,
                 colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(tbl)
        elif ctrl["status"] == "pass":
            story.append(Paragraph(
                "<i>No findings — all checks are passing.</i>",
                body_style))
        else:
            story.append(Paragraph(
                "<i>No evidence — control is not applicable (no scan has run).</i>",
                body_style))
        story.append(Spacer(1, 14))

    # Footer
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "<i>Generated from live GitHub posture findings mapped to "
        "SOC 2 Trust Services Criteria.</i>",
        ParagraphStyle("Footer", parent=body_style, fontSize=7,
                       textColor=colors.HexColor("#94a3b8"))))

    doc.build(story)
    return buf.getvalue()

