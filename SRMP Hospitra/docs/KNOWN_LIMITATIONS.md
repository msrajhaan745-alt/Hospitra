# Known limitations

Hospitra is a localhost demonstrator. These limitations are known and intentional unless stated otherwise.

## Scope and safety (by design)
- **Synthetic data only.** No live discovery, scanning, packet capture, log ingestion, external threat intelligence or integration with real hospital systems. There is no event-ingestion API.
- **Containment is a recorded state**, not an action.
- **No compliance claim.** Inherent and residual scores are illustrative qualitative ratings, not calibrated probabilities or certified assessments; control effectiveness is a judgement, not a measurement.
- **No machine learning**; eight fixed deterministic rules.

## Authentication (Version 2)
- Served over **plain HTTP on localhost**. Before any network exposure: put it behind HTTPS, set `HOSPITRA_COOKIE_SECURE=true`, and commission an independent security review. V2 has not been penetration-tested.
- **No MFA, no SSO/LDAP, no self-service password reset or e-mail**; an Admin resets passwords.
- CSRF protection relies on the `SameSite=Strict` session cookie and JSON request bodies; there is no separate CSRF token.
- Sign-in throttling (5 failures per username per 15 minutes) is **in-memory**: it resets when the server restarts and is per process.
- Sessions have an **absolute** lifetime (default 8 h); there is no idle timeout. Expired/revoked session rows are not purged automatically.
- Roles are fixed (Viewer / Analyst / Admin); there is no per-branch or per-record access control.
- `/docs` (OpenAPI) is public; it shows the schema only — calling endpoints still requires a session.
- The UI hides actions a role cannot perform, but the server is the enforcement point.

## Functional
- Residual model: only the strongest control per axis counts (no cumulative effect by design); effectiveness has two levels (Partial/Substantial); there is no control-testing evidence, review date or cost.
- Threat–vulnerability pairings and control↔vulnerability "addresses" links are informative only; they do not restrict which risks/controls can be linked.
- Detection rules are defined in code; their `enabled` flag cannot be toggled through the UI/API.
- Threshold rules (R2, R7) fire once per source per evaluation window; repeated triggers within the window are recorded but suppressed.
- Scenario content is deterministic, but timestamps and UUIDs come from the trigger time.
- Incidents are created automatically only; no cross-event correlation.
- No delete operation for assets, catalogue entries, controls or users (deactivate instead). Risk–control *links* can be removed.
- Branch status (Normal/Elevated/Critical) is a simple documented derivation.
- Risk context is computed when viewed (not a snapshot at detection time).
- The data reset clears the audit log (user accounts are kept); it is recorded by a single `data.reset` entry.
- Asset IP sorting is lexicographic. All timestamps are displayed in UTC.

## Technical
- SQLite: one writer at a time; suitable for a handful of local users, not concurrent multi-user load.
- WebSocket notifications are not persisted or replayed; after a reconnect the UI re-reads from REST.
- Desktop-first layout; the risk register table is wide (inherent + residual columns) and scrolls horizontally on narrow screens.
- The optional `ui-tests/` need Node.js ≥ 22 and Chrome/Edge; they create test users and reset demo data, so run them against a throwaway server.
