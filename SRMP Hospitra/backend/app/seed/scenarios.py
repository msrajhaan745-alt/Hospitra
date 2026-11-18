"""Predefined, deterministic simulation scenarios (spec §10.1).

Each scenario is a pure function of (branch, trigger time) that returns event
drafts. Nothing here touches a network interface, executes commands or contacts any
external destination: "external" addresses come from the IETF documentation ranges
198.51.100.0/24 and 203.0.113.0/24, which are reserved and never routed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.constants import BASELINE_SCENARIO_ID, EventType
from app.models import Asset, Branch, NetworkZone
from app.services.event_service import EventDraft


@dataclass
class ScenarioContext:
    branch: Branch
    assets: dict[str, Asset]          # "CLN-001" -> Asset
    zones: dict[str, NetworkZone]     # "CLN" -> NetworkZone
    base_time: datetime

    @property
    def site(self) -> int:
        return self.branch.site_id

    def a(self, key: str) -> Asset:
        return self.assets[key]


def build_context(db: Session, branch: Branch, base_time: datetime) -> ScenarioContext:
    zones = {z.code: z for z in db.scalars(select(NetworkZone).where(NetworkZone.branch_id == branch.id))}
    assets = {}
    prefix = f"HSP-{branch.code}-"
    for asset in db.scalars(select(Asset).where(Asset.branch_id == branch.id, Asset.asset_tag.like(f"{prefix}%"))):
        assets[asset.asset_tag.removeprefix(prefix)] = asset
    return ScenarioContext(branch=branch, assets=assets, zones=zones, base_time=base_time)


def _draft(ctx: ScenarioContext, scenario_id: str, offset_s: int, **kw) -> EventDraft:
    return EventDraft(branch_id=ctx.branch.id, scenario_id=scenario_id,
                      occurred_at=ctx.base_time + timedelta(seconds=offset_s), **kw)


# ---- S1–S8 --------------------------------------------------------------------------------

def _s1(ctx: ScenarioContext) -> list[EventDraft]:
    src, dst = ctx.a("GST-002"), ctx.a("APP-001")
    return [_draft(
        ctx, "S1", 0, event_type=EventType.NETWORK_ACCESS,
        source_asset_id=src.id, destination_asset_id=dst.id,
        message=f"Connection attempt from guest device {src.asset_tag} to {dst.asset_tag} on TCP/443.",
        metadata={"protocol": "TCP", "destination_port": 443, "application": "Clinical records web interface",
                  "firewall_action": "denied", "direction": "guest → application/data"},
    )]


def _s2(ctx: ScenarioContext) -> list[EventDraft]:
    src, dst = ctx.a("ADM-001"), ctx.a("NET-002")
    return [
        _draft(ctx, "S2", -200 + i * 50, event_type=EventType.AUTH_FAILURE,
               source_asset_id=src.id, destination_asset_id=dst.id,
               message=f"Failed SSH authentication #{i + 1} for account 'adm.netops-svc' "
                       f"from {src.asset_tag} to {dst.asset_tag}.",
               metadata={"account": "adm.netops-svc", "auth_protocol": "SSH", "failure_reason": "invalid password",
                         "attempt": i + 1})
        for i in range(5)
    ]


def _s3(ctx: ScenarioContext) -> list[EventDraft]:
    gw = ctx.a("DMZ-002")
    return [_draft(
        ctx, "S3", 0, event_type=EventType.VPN_LOGIN,
        source_ip="198.51.100.23", destination_asset_id=gw.id,
        message=f"VPN login for 'clin.remote07' via {gw.asset_tag} from an unrecognised region "
                f"on an unmanaged device.",
        metadata={"user": "clin.remote07", "login_region": "Unrecognised region",
                  "approved_regions": ["Home region"], "device_posture": "unmanaged",
                  "mfa_used": False, "session_result": "success"},
    )]


def _s4(ctx: ScenarioContext) -> list[EventDraft]:
    zone, switch = ctx.zones["MED"], ctx.a("NET-001")
    return [_draft(
        ctx, "S4", 0, event_type=EventType.DEVICE_OBSERVED,
        source_zone_id=zone.id, source_ip=f"10.{ctx.site}.50.199",
        message=f"Unregistered device observed in {zone.name} (VLAN {zone.vlan_id}).",
        metadata={"mac_address": "02:00:5E:10:00:C7", "hostname": "UNKNOWN-DEVICE",
                  "observed_by": f"{switch.asset_tag} (NAC/DHCP record)", "dhcp_lease": True},
    )]


def _s5(ctx: ScenarioContext) -> list[EventDraft]:
    src = ctx.a("APP-002")
    return [_draft(
        ctx, "S5", 0, event_type=EventType.OUTBOUND_TRANSFER,
        source_asset_id=src.id, destination_ip="203.0.113.45",
        message=f"Outbound transfer of 2048 MB from {src.asset_tag} to external host 203.0.113.45.",
        metadata={"bytes_out": 2_147_483_648, "baseline_bytes_out_24h": 52_428_800, "protocol": "HTTPS",
                  "duration_seconds": 540, "destination_category": "Uncategorised external host"},
    )]


def _s6(ctx: ScenarioContext) -> list[EventDraft]:
    portal = ctx.a("DMZ-001")
    return [_draft(
        ctx, "S6", 0, event_type=EventType.REQUEST_VOLUME,
        source_ip="203.0.113.0/24", destination_asset_id=portal.id,
        message=f"Request-volume spike: 48,000 requests/min to {portal.asset_tag} (patient portal).",
        metadata={"requests_per_minute": 48_000, "baseline_requests_per_minute": 1_200,
                  "distinct_source_ips": 3_150, "http_5xx_rate": 0.27, "measurement_window_seconds": 60},
    )]


_S7_STEPS = (
    ("file_read", 3, "\\\\shared\\rota\\ward-rota.xlsx"),
    ("shadow_copy_delete", 0, "volume shadow copies"),
    ("mass_rename", 420, "\\\\shared\\clinical-admin\\*.locked"),
    ("mass_rename", 880, "\\\\shared\\finance\\*.locked"),
    ("high_entropy_write", 1_200, "\\\\shared\\*"),
    ("ransom_note_create", 1, "\\\\shared\\README_RESTORE.txt"),
)


def _s7(ctx: ScenarioContext) -> list[EventDraft]:
    src, share = ctx.a("CLN-001"), ctx.a("ADM-002")
    return [
        _draft(ctx, "S7", -50 + i * 10, event_type=EventType.FILE_ACTIVITY,
               source_asset_id=src.id, destination_asset_id=share.id,
               message=f"File activity '{op}' by {src.asset_tag} on {share.asset_tag} ({n} file(s)).",
               metadata={"process": "unknown_payload.exe", "operation": op, "files_affected": n,
                         "path": f"{share.asset_tag}{path}"})
        for i, (op, n, path) in enumerate(_S7_STEPS)
    ]


def _s8(ctx: ScenarioContext) -> list[EventDraft]:
    target, gw = ctx.a("MED-002"), ctx.a("DMZ-002")
    day = (ctx.base_time - timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0)
    return [_draft(
        ctx, "S8", 0, event_type=EventType.VENDOR_ACCESS,
        source_ip="198.51.100.77", destination_asset_id=target.id,
        message=f"Vendor remote session to {target.asset_tag} outside its approved maintenance window.",
        metadata={"vendor": "MedTech Support Services", "account": "vendor.medtech01",
                  "approved_window_start": day.isoformat(), "approved_window_end": (day + timedelta(hours=3)).isoformat(),
                  "access_path": gw.asset_tag, "change_ticket": "CHG-0042"},
    )]


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    name: str
    description: str
    expected_rule_id: str
    source_description: str
    destination_description: str
    build: Callable[[ScenarioContext], list[EventDraft]]
    event_count: int = 1


SCENARIOS: tuple[Scenario, ...] = (
    Scenario("S1", "Guest-to-Clinical Access Attempt",
             "A guest Wi-Fi kiosk attempts to reach the clinical records application server in the Application/Data zone.",
             "R1", "Guest Lounge Kiosk (Guest Wi-Fi, VLAN 60)", "Clinical Records Application Server (VLAN 40)", _s1),
    Scenario("S2", "Repeated Authentication Failures",
             "Five failed SSH logins for one service account from an administration workstation within ~4 minutes.",
             "R2", "Administration Workstation (VLAN 20)", "Network Management Server (VLAN 10)", _s2, event_count=5),
    Scenario("S3", "Unusual VPN Login",
             "A successful VPN login from an unrecognised region on an unmanaged device, without MFA.",
             "R3", "External address 198.51.100.23", "Remote Access VPN Gateway (DMZ)", _s3),
    Scenario("S4", "Unknown Device in Sensitive Zone",
             "An unregistered device obtains an address in the Medical Devices zone.",
             "R4", "Unregistered device 10.<site>.50.199", "Medical Devices zone (VLAN 50)", _s4),
    Scenario("S5", "Unusual Outbound Transfer",
             "The clinical database server sends 2 GB to an uncategorised external host.",
             "R5", "Clinical Database Server (VLAN 40)", "External 203.0.113.45", _s5),
    Scenario("S6", "DDoS-like Request Volume",
             "The public patient portal receives ~40× its normal request rate from thousands of sources.",
             "R6", "203.0.113.0/24", "Patient Portal Web Server (DMZ)", _s6),
    Scenario("S7", "Ransomware-like Behaviour",
             "A clinical workstation deletes shadow copies, mass-renames and rewrites files on a file share, "
             "then drops a ransom note.",
             "R7", "Ward Nurse Station Workstation (VLAN 30)", "Office File Server (VLAN 20)", _s7,
             event_count=len(_S7_STEPS)),
    Scenario("S8", "Vendor Access Outside Approved Window",
             "A vendor support account connects to a medical device after its approved maintenance window ended.",
             "R8", "Vendor 198.51.100.77 via VPN gateway", "Medical device (VLAN 50)", _s8),
)

SCENARIOS_BY_ID: dict[str, Scenario] = {s.scenario_id: s for s in SCENARIOS}


# ---- benign baseline activity (seed history only) --------------------------------------------

def _b(ctx, t, **kw) -> EventDraft:
    return EventDraft(branch_id=ctx.branch.id, scenario_id=BASELINE_SCENARIO_ID, occurred_at=t, **kw)


def _baseline_templates(ctx: ScenarioContext, t: datetime) -> list[Callable[[], EventDraft]]:
    a = ctx.a
    return [
        lambda: _b(ctx, t, event_type=EventType.NETWORK_ACCESS, source_asset_id=a("CLN-001").id,
                   destination_asset_id=a("APP-001").id, message="Clinical workstation session to the clinical records application (approved path).",
                   metadata={"protocol": "TCP", "destination_port": 443, "firewall_action": "allowed"}),
        lambda: _b(ctx, t, event_type=EventType.NETWORK_ACCESS, source_asset_id=a("MED-001").id,
                   destination_asset_id=a("APP-001").id, message="Medical device gateway message to the clinical application (approved path).",
                   metadata={"protocol": "TCP", "destination_port": 2575, "firewall_action": "allowed"}),
        lambda: _b(ctx, t, event_type=EventType.TELEMETRY, source_asset_id=a("NET-001").id,
                   destination_asset_id=a("SEC-001").id, message="Security telemetry batch forwarded to the SIEM log collector.",
                   metadata={"protocol": "syslog-tls", "records": 1840}),
        lambda: _b(ctx, t, event_type=EventType.AUTH_FAILURE, source_asset_id=a("ADM-001").id,
                   destination_asset_id=a("APP-001").id, message="Single failed application login (mistyped password).",
                   metadata={"account": "staff.user14", "auth_protocol": "HTTPS form", "failure_reason": "invalid password", "attempt": 1}),
        lambda: _b(ctx, t, event_type=EventType.VPN_LOGIN, source_ip="198.51.100.10", destination_asset_id=a("DMZ-002").id,
                   message="VPN login from an approved region on a managed device.",
                   metadata={"user": "clin.remote02", "login_region": "Home region", "approved_regions": ["Home region"],
                             "device_posture": "managed", "mfa_used": True, "session_result": "success"}),
        lambda: _b(ctx, t, event_type=EventType.OUTBOUND_TRANSFER, source_asset_id=a("SEC-002").id, destination_ip="203.0.113.10",
                   message="Incremental off-site backup replication (approved destination).",
                   metadata={"bytes_out": 125_829_120, "baseline_bytes_out_24h": 120_000_000, "protocol": "HTTPS"}),
        lambda: _b(ctx, t, event_type=EventType.REQUEST_VOLUME, source_ip="203.0.113.0/24", destination_asset_id=a("DMZ-001").id,
                   message="Patient portal request volume within its normal range.",
                   metadata={"requests_per_minute": 1_420, "baseline_requests_per_minute": 1_200, "distinct_source_ips": 260,
                             "http_5xx_rate": 0.002, "measurement_window_seconds": 60}),
        lambda: _b(ctx, t, event_type=EventType.FILE_ACTIVITY, source_asset_id=a("CLN-002").id, destination_asset_id=a("ADM-002").id,
                   message="Routine document save to the office file share.",
                   metadata={"process": "office_suite.exe", "operation": "file_save", "files_affected": 1, "path": "\\\\shared\\letters"}),
        lambda: _b(ctx, t, event_type=EventType.VENDOR_ACCESS, source_ip="198.51.100.77", destination_asset_id=a("MED-002").id,
                   message="Vendor maintenance session inside its approved window.",
                   metadata={"vendor": "MedTech Support Services", "account": "vendor.medtech01",
                             "approved_window_start": (t - timedelta(hours=1)).isoformat(),
                             "approved_window_end": (t + timedelta(hours=1)).isoformat(),
                             "access_path": a("DMZ-002").asset_tag, "change_ticket": "CHG-0031"}),
        lambda: _b(ctx, t, event_type=EventType.DEVICE_OBSERVED, source_asset_id=a("CLN-002").id,
                   message="Registered clinical workstation re-associated with the network.",
                   metadata={"mac_address": "02:00:5E:10:00:21", "hostname": a("CLN-002").asset_tag, "dhcp_lease": True,
                             "observed_by": a("NET-001").asset_tag}),
        lambda: _b(ctx, t, event_type=EventType.NETWORK_ACCESS, source_asset_id=a("GST-002").id, destination_ip="198.51.100.50",
                   message="Guest kiosk web browsing to the internet (permitted for guests).",
                   metadata={"protocol": "TCP", "destination_port": 443, "firewall_action": "allowed"}),
    ]


def baseline_drafts(ctx: ScenarioContext, branch_index: int, days: int = 7, per_day: int = 4) -> list[EventDraft]:
    """Deterministic benign events: `per_day` per branch per day for the last `days` days."""
    drafts: list[EventDraft] = []
    for d in range(days):
        for k in range(per_day):
            t = ctx.base_time - timedelta(days=d, hours=2 + 5 * k + branch_index, minutes=7 * k + 3 * branch_index)
            templates = _baseline_templates(ctx, t)
            drafts.append(templates[(d * 3 + branch_index * 5 + k * 3) % len(templates)]())
    return sorted(drafts, key=lambda x: x.occurred_at)
