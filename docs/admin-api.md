# Local admin API (first functional slice)

Opt-in serving: `-admin-token-file <private-file>` enables `/admin` and
`/admin/api/*` on the loopback listener only. The file must be private, regular,
exactly 43 canonical base64url bytes representing a separate 32-byte synthetic
authority. It must not equal any gateway entry token. The program does not create
or persist this authority. All API calls use `Authorization: Bearer ...`; no
query credentials, cookie authentication, role headers, or entry-token fallback.
This is a **single operator authority**, not multi-admin IAM. Audit actor is
`operator`; audit subject identifies the affected user, not a human admin.

Every request is checked for loopback peer, exact configured Host, allowed
Origin/Fetch metadata, no query, and unambiguous auth. Mutating/read-body calls
use POST with `Content-Type: application/json` and `X-MCP-Admin: 1`.
Browser POSTs require same-origin metadata. Bodies are at most 64 KiB, strict
single JSON objects with duplicate/unknown fields rejected. Four admin requests
may run concurrently. Responses and errors are no-store; no credentials or
credential hashes are returned. Assets are an unauthenticated static shell;
all data APIs require the separate authority.

## Routes

- `GET /admin/api/snapshot`: actual configured services, authoritative users,
  policies, entry state, binding metadata, current discovered tool catalog,
  audit status and process-lifetime rejection counters. Snake-case fields
  except the existing `RejectionStatus` (`Started`, `HTTP`, `Operations`, each
  counter `Count`, `Last`, `Saturated`). Capability booleans explicitly gate UI.
  `health: not_checked` is not a health probe. `metrics.latency_p95` and
  `metrics.success_rate` are null: no invented KPI denominator.
- `POST /admin/api/audit` `{ "after": 0, "limit": 100 }`: bounded audit page,
  `{events,dropped,last_sequence}`; metadata only, keyed opaque subject IDs.
  Audit loss/retention capacity and pending/unknown outcomes remain visible.
- `POST /admin/api/mutate`: `{action,tenant,principal,expected_version,
  system?,allowed?,preview?,confirm?}`. Actions `set_policy`,
  `disable_principal`, `revoke_binding`. Policy/disable use policy version;
  binding revoke uses binding generation. Exactly one of preview/confirm must
  be true. Preview validates current CAS without mutation; confirm performs a
  fresh CAS under existing authenticated transaction locks. The UI previews
  and then explicitly confirms. Success is `{applied:true}`; reload snapshot.
  Existing persistent transactions commit state and operator audit together;
  all revocation/policy generations survive restart. Without a DB this state
  is explicitly volatile (`persistent:false`). Disabling is irreversible in
  this first online interface; it revokes all provider bindings.
- `POST /admin/api/config/validate` `{systems:[System]}`: validates against the
  real existing auth/network/topology constructor, without network probes.
  Returns `{valid:true,applied:false,state:"not_applied",
  reason:"topology_migration_required",draft:{systems:[...]}}`.
  This is a stateless validation/export operation, not a saved server draft or
  live configuration change. Credentials and users are not accepted here.

## Explicit unsupported operations

Gateway entry issuance/rotation/revocation remain the trusted **offline**
maintenance primitives, not online mutations. Online user creation and live
upstream topology application are unavailable: persistent storage authenticates
systems, identity sets and network/auth settings in its topology fingerprint.
Changing config then restarting is not a supported migration and fails closed.
Do not delete/reinitialize a DB to work around this restriction. Export is a
reviewable proposal only; a safe topology migration is future work.

## Errors / uncertain outcomes

Errors are `{error:code}` with bounded fixed codes: 400 invalid_request or
invalid_configuration; 401 admin_authentication_rejected; 403 request_denied or
permission_denied; 409 version_conflict; 413 request_too_large; 415 json_required;
429 admin_busy; 501 unsupported_operation; 503 state_unavailable or
audit_capacity_exhausted. Never retry a confirmed write blindly after a network
or storage error: its commit may have occurred. Re-read authoritative status and
audit; if storage failed closed, reopen and inspect before another mutation.

Tests use only synthetic authority/data and temporary SQLite stores. No real
account credentials are generated, installed, or exercised by this implementation.
