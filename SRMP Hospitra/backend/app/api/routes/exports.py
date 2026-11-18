from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import Response

from app.api.dependencies import DbSession
from app.core.time import utcnow
from app.services import export_service

router = APIRouter(prefix="/exports", tags=["exports"])


def _filename(stem: str, ext: str) -> str:
    return f"hospitra-{stem}-{utcnow().strftime('%Y%m%dT%H%M%SZ')}.{ext}"


def _csv_response(content: str, stem: str) -> Response:
    return Response(
        content=content.encode("utf-8-sig"),  # BOM so spreadsheet tools detect UTF-8
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_filename(stem, "csv")}"'},
    )


@router.get("/assets.csv", summary="Asset inventory (CSV)")
def assets_csv(db: DbSession):
    return _csv_response(export_service.assets_csv(db), "assets")


@router.get("/risks.csv", summary="Risk register (CSV)")
def risks_csv(db: DbSession):
    return _csv_response(export_service.risks_csv(db), "risks")


@router.get("/events.csv", summary="Security events (CSV)")
def events_csv(db: DbSession):
    return _csv_response(export_service.events_csv(db), "events")


@router.get("/incidents.csv", summary="Incidents (CSV)")
def incidents_csv(db: DbSession):
    return _csv_response(export_service.incidents_csv(db), "incidents")


@router.get("/summary.pdf", summary="Summary report (PDF)")
def summary_pdf(db: DbSession):
    return Response(
        content=export_service.summary_pdf(db),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{_filename("summary", "pdf")}"'},
    )
