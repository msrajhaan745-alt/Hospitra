"""CSV and PDF exports built from the same services the API uses (no duplicated logic)."""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from app.core.time import utcnow
from app.services import dashboard_service, event_service, incident_service, risk_service
from app.services.asset_service import list_assets
from app.services.common import PageParams

EXPORT_PAGE = PageParams(limit=10_000, offset=0)


def _ts(value: datetime | None) -> str:
    """Machine-readable UTC ISO 8601 (CSV)."""
    return value.isoformat().replace("+00:00", "Z") if value else ""


def _display_ts(value: datetime | None) -> str:
    """Human-readable UTC timestamp (PDF)."""
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else "—"


def _csv(header: list[str], rows: list[list[Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return buffer.getvalue()


def assets_csv(db: Session) -> str:
    items, _ = list_assets(db, EXPORT_PAGE)
    header = ["asset_tag", "name", "asset_type", "branch", "zone", "vlan_id", "ip_address", "operating_system",
              "owner", "criticality", "data_classification", "confidentiality", "integrity", "availability",
              "status", "last_seen_at_utc", "created_at_utc", "updated_at_utc"]
    rows = [[a.asset_tag, a.name, a.asset_type.value, a.branch_code, a.zone_name, a.vlan_id, a.ip_address,
             a.operating_system, a.owner, a.criticality.value, a.data_classification.value, a.confidentiality,
             a.integrity, a.availability, a.status.value, _ts(a.last_seen_at), _ts(a.created_at), _ts(a.updated_at)]
            for a in items]
    return _csv(header, rows)


def risks_csv(db: Session) -> str:
    items, _ = risk_service.list_risks(db, EXPORT_PAGE, sort="risk_score", order="desc")
    header = ["risk_reference", "asset_tag", "asset_name", "branch", "threat_code", "threat", "vulnerability_code",
              "vulnerability", "likelihood", "confidentiality_impact", "integrity_impact", "availability_impact",
              "overall_impact", "risk_score", "severity", "residual_likelihood", "residual_impact", "residual_score",
              "residual_severity", "implemented_controls", "planned_controls", "treatment", "owner", "status",
              "created_at_utc", "updated_at_utc"]
    rows = [[r.reference, r.asset.asset_tag, r.asset.name, r.asset.branch_code, r.threat.code, r.threat.name,
             r.vulnerability.code, r.vulnerability.name, r.likelihood, r.confidentiality_impact, r.integrity_impact,
             r.availability_impact, r.overall_impact, r.risk_score, r.severity.value, r.residual_likelihood,
             r.residual_impact, r.residual_score, r.residual_severity.value,
             ";".join(f"{c.code}:{c.effectiveness.value}" for c in r.controls if c.counted),
             ";".join(c.code for c in r.controls if not c.counted),
             r.treatment.value, r.owner, r.status.value, _ts(r.created_at), _ts(r.updated_at)] for r in items]
    return _csv(header, rows)


def events_csv(db: Session) -> str:
    items, _ = event_service.list_events(db, EXPORT_PAGE)
    header = ["event_id", "occurred_at_utc", "event_type", "branch", "source_asset", "source_zone", "source_ip",
              "destination_asset", "destination_zone", "destination_ip", "severity", "detection_status",
              "matched_rules", "scenario_id", "message"]
    rows = [[e.id, _ts(e.occurred_at), e.event_type.value, e.branch_code,
             e.source_asset.asset_tag if e.source_asset else "", e.source_zone.name if e.source_zone else "",
             e.source_ip or "", e.destination_asset.asset_tag if e.destination_asset else "",
             e.destination_zone.name if e.destination_zone else "", e.destination_ip or "", e.severity.value,
             e.detection_status, ";".join(m.rule_id for m in e.matched_rules),
             e.scenario_id, e.message] for e in items]
    return _csv(header, rows)


def incidents_csv(db: Session) -> str:
    items, _ = incident_service.list_incidents(db, EXPORT_PAGE)
    header = ["incident_number", "title", "severity", "status", "assigned_to", "branch", "rule_id", "rule_name",
              "asset_tags", "event_count", "created_at_utc", "updated_at_utc", "resolved_at_utc", "closed_at_utc",
              "resolution_notes"]
    rows = [[i.incident_number, i.title, i.severity.value, i.status.value, i.assigned_to or "", i.branch_code or "",
             i.rule_id, i.rule_name, ";".join(i.asset_tags), i.event_count, _ts(i.created_at), _ts(i.updated_at),
             _ts(i.resolved_at), _ts(i.closed_at), (i.resolution_notes or "").replace("\n", " ")] for i in items]
    return _csv(header, rows)


# ---- PDF ---------------------------------------------------------------------------------------

NAVY = colors.HexColor("#0B1726")
TEAL = colors.HexColor("#0E7C86")
GRID = colors.HexColor("#C9D3DD")
SEVERITY_COLOURS = {
    "Low": colors.HexColor("#2E7D6B"),
    "Moderate": colors.HexColor("#9A6B00"),
    "High": colors.HexColor("#B34700"),
    "Critical": colors.HexColor("#B00020"),
}


class _NumberedCanvas(rl_canvas.Canvas):
    """Adds "Page X of Y" and the report footer to every page."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_pages: list[dict] = []

    def showPage(self):  # noqa: N802 (reportlab API)
        self._saved_pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_pages)
        for state in self._saved_pages:
            self.__dict__.update(state)
            width, _ = self._pagesize
            self.setFont("Helvetica", 7.5)
            self.setFillColor(colors.HexColor("#5B6B7C"))
            self.drawString(14 * mm, 9 * mm, "Hospitra — Security & Risk Summary Report")
            self.drawRightString(width - 14 * mm, 9 * mm, f"Page {self._pageNumber} of {total}")
            super().showPage()
        super().save()


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], alignment=TA_LEFT, fontSize=19, textColor=NAVY, spaceAfter=2),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=9, textColor=colors.HexColor("#4A5A6A")),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=12.5, textColor=NAVY, spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=8.5, leading=11),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontSize=7.5, leading=9.5),
    }


def _table(rows: list[list[Any]], widths: list[float], severity_col: int | None = None) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F3F6F9")]),
    ]
    if severity_col is not None:
        for r, row in enumerate(rows[1:], start=1):
            label = str(row[severity_col])
            if label in SEVERITY_COLOURS:
                style += [("TEXTCOLOR", (severity_col, r), (severity_col, r), SEVERITY_COLOURS[label]),
                          ("FONTNAME", (severity_col, r), (severity_col, r), "Helvetica-Bold")]
    table.setStyle(TableStyle(style))
    return table


def summary_pdf(db: Session) -> bytes:
    s = _styles()
    generated = utcnow()
    summary = dashboard_service.summary(db)
    risks, risk_total = risk_service.list_risks(db, PageParams(limit=15, offset=0), sort="risk_score", order="desc")
    incidents, _ = incident_service.list_incidents(db, PageParams(limit=25, offset=0))
    distribution = dashboard_service.risk_distribution(db)

    def p(text: str) -> Paragraph:
        return Paragraph(text, s["cell"])

    story: list[Any] = [
        Paragraph("Hospitra — Security &amp; Risk Summary Report", s["title"]),
        Paragraph(f"Hospital Network Security &amp; Risk Monitoring Platform · Generated {_display_ts(generated)}", s["sub"]),
        Spacer(1, 6),
        Paragraph("1. Overview", s["h2"]),
    ]
    a, inc, ev, det = summary["assets"], summary["incidents"], summary["events"], summary["detections"]
    story.append(_table([
        ["Metric", "Value", "Metric", "Value"],
        ["Total assets", a["total"], "Open incidents (Open/Investigating/Contained)", inc["open_total"]],
        ["Active / Warning", f"{a['active']} / {a['warning']}", "Total incidents", inc["total"]],
        ["Offline / Maintenance", f"{a['offline']} / {a['maintenance']}", "Security events recorded", ev["total"]],
        ["Risks", risk_total, "Matched detections (alerts)", det["matched_total"]],
    ], [45 * mm, 30 * mm, 75 * mm, 30 * mm]))

    story.append(Paragraph("2. Branch status", s["h2"]))
    rows = [["Branch", "Role", "Assets", "Open incidents", "Status", "Basis"]]
    for b in summary["branches"]:
        rows.append([p(b["name"]), p(b["role"]), b["assets_total"], b["open_incidents"], b["posture"], p(b["posture_reason"])])
    story.append(_table(rows, [42 * mm, 38 * mm, 14 * mm, 22 * mm, 18 * mm, 46 * mm]))

    story.append(Paragraph("3. Risk severity distribution", s["h2"]))
    story.append(Paragraph("Severity bands: 1–4 Low · 5–9 Moderate · 10–16 High · 17–25 Critical. "
                           "Inherent score = Likelihood × max(Confidentiality, Integrity, Availability). "
                           "Residual score applies only implemented controls: preventive controls lower likelihood, "
                           "detective/corrective controls lower impact (Partial 1 level, Substantial 2; strongest "
                           "control per axis; minimum 1).", s["body"]))
    story.append(Spacer(1, 4))
    rows = [["Severity", "Inherent risks", "Residual risks"]] + [
        [sev, n, distribution["residual_by_severity"][sev]] for sev, n in distribution["by_severity"].items()
    ]
    story.append(_table(rows, [40 * mm, 30 * mm, 30 * mm], severity_col=0))

    story.append(Paragraph(f"4. Highest-scoring risks (top {len(risks)} of {risk_total})", s["h2"]))
    rows = [["Ref", "Asset", "Threat / Vulnerability", "L", "C", "I", "A", "Impact", "Score", "Severity", "Residual", "Status"]]
    for r in risks:
        counted = [c.code for c in r.controls if c.counted]
        residual = f"{r.residual_score} {r.residual_severity.value}" + (f"<br/>({', '.join(counted)})" if counted else "")
        rows.append([r.reference, p(f"{r.asset.asset_tag}<br/>{r.asset.name}"),
                     p(f"{r.threat.code} {r.threat.name}<br/>{r.vulnerability.code} {r.vulnerability.name}"),
                     r.likelihood, r.confidentiality_impact, r.integrity_impact, r.availability_impact,
                     r.overall_impact, r.risk_score, r.severity.value, p(residual), r.status.value])
    # Column widths sum to 182 mm = A4 width minus 2 × 14 mm margins.
    story.append(_table(rows, [15 * mm, 30 * mm, 40 * mm, 6 * mm, 6 * mm, 6 * mm, 6 * mm, 11 * mm, 10 * mm, 15 * mm, 22 * mm, 15 * mm],
                        severity_col=9))

    story.append(Paragraph(f"5. Incidents ({len(incidents)} most recent)", s["h2"]))
    if incidents:
        rows = [["Incident", "Title", "Severity", "Status", "Assigned", "Created (UTC)"]]
        for i in incidents:
            rows.append([i.incident_number, p(i.title), i.severity.value, i.status.value, p(i.assigned_to or "—"),
                         p(_display_ts(i.created_at))])
        story.append(_table(rows, [17 * mm, 70 * mm, 17 * mm, 21 * mm, 25 * mm, 32 * mm], severity_col=2))
    else:
        story.append(Paragraph("No incidents recorded.", s["body"]))

    story.append(Paragraph("6. Recent detections", s["h2"]))
    if summary["recent_detections"]:
        rows = [["Rule", "Severity", "Branch", "Event time (UTC)", "Explanation"]]
        for d in summary["recent_detections"]:
            rows.append([p(f"{d['rule_id']} {d['rule_name']}"), d["severity"].value if hasattr(d["severity"], "value") else d["severity"],
                         d["event"]["branch_code"], p(_display_ts(d["event"]["occurred_at"])), p(d["explanation"])])
        story.append(_table(rows, [34 * mm, 16 * mm, 13 * mm, 28 * mm, 91 * mm], severity_col=1))
    else:
        story.append(Paragraph("No detections recorded.", s["body"]))

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm,
                            bottomMargin=16 * mm, title="Hospitra Summary Report",
                            author="Hospitra", subject="Security & risk summary report")
    doc.build(story, canvasmaker=_NumberedCanvas)
    return buffer.getvalue()
