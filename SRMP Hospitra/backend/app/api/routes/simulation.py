from __future__ import annotations

from fastapi import APIRouter, status
from starlette.concurrency import run_in_threadpool

from app.api.dependencies import Actor, AdminActor, DbSession, Pagination
from app.schemas.common import Page
from app.schemas.simulation import ResetRequest, ScenarioRead, SimulationRunRead, TriggerRequest, TriggerResponse
from app.seed.seeder import reset_data
from app.services import simulation_service
from app.websocket.manager import manager

router = APIRouter(prefix="/simulation", tags=["simulation"])


@router.get("/scenarios", response_model=list[ScenarioRead], summary="The eight predefined scenarios")
def list_scenarios():
    return simulation_service.list_scenarios()


@router.post("/trigger", response_model=TriggerResponse, status_code=status.HTTP_201_CREATED,
             summary="Run a scenario: generate → persist → detect → risk context → incident → audit → notify")
async def trigger(payload: TriggerRequest, db: DbSession, actor: Actor):
    result = await run_in_threadpool(
        simulation_service.run_scenario, db, payload.scenario_id, payload.branch_code, actor=actor
    )
    run = simulation_service.run_to_read(result.run, {result.run.branch_id: payload.branch_code})
    response = TriggerResponse(
        run=run,
        event_ids=[e.id for e in result.events],
        matched_detection_ids=[d.id for d in result.matched],
        incident_ids=[i.id for i in result.incidents],
        summary=result.summary,
    )
    # Published only after run_scenario has committed successfully.
    await manager.broadcast("simulation.completed", {
        "run_id": run.id, "scenario_id": run.scenario_id, "scenario_name": run.scenario_name,
        "branch_code": run.branch_code, "event_ids": response.event_ids,
        "matched_detection_ids": response.matched_detection_ids,
        "incidents": [{"id": i.id, "incident_number": i.incident_number, "severity": i.severity.value}
                      for i in result.incidents],
        "summary": result.summary,
    })
    return response


@router.get("/history", response_model=Page[SimulationRunRead], summary="Recent simulation runs")
def history(db: DbSession, page: Pagination):
    items, total = simulation_service.list_history(db, page)
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.post("/reset", summary='Admin: delete all data (users are kept) and reseed (body: {"confirm": "RESET"})')
async def reset(payload: ResetRequest, db: DbSession, actor: AdminActor) -> dict:
    report = await run_in_threadpool(reset_data, db, actor)
    await manager.broadcast("data.reset", {"created": report.created})
    return {"status": "reset", "created": report.created}
