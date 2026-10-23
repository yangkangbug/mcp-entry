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

## Online operations and remaining limits

Persistent online instances now support managed user creation and entry token
issuance/rotation/revocation through the separately confirmed lifecycle endpoint
below. Service additions and timeout-only changes use the authenticated runtime
registry and dedicated current/preview/apply endpoints documented in
[runtime service configuration](runtime-service-config.md). The legacy validate
endpoint remains stateless and does not apply a configuration.

Existing service endpoint/auth/network/quota changes, deletion and renaming are
still unsupported. Keep the original bootstrap configuration as the deployment
anchor; do not overwrite it with the effective runtime registry, delete the DB,
or reinitialize storage to bypass an incompatibility. Offline maintenance remains
available for its documented operations, not as a substitute for online CAS.

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

## Managed users and entry credentials

`POST /admin/api/lifecycle` uses the same separate admin bearer, loopback/origin
checks and `X-MCP-Admin: 1` as other admin writes. Available only on an online,
persistent gateway; inspect `capabilities.user_create` and `entry_lifecycle`.
Unknown/duplicate JSON fields are rejected. Requests contain:

```json
{"action":"rotate_entry","tenant":"example","principal":"person","expected_generation":1,"expires_at":"2030-01-01T00:00:00Z","preview":true}
```

Actions: `create_user` requires generation 0 and no expiry; `issue_entry`
requires a revoked entry; `rotate_entry` requires a non-revoked entry;
`revoke_entry` requires a non-revoked entry and no expiry. Issue/rotate require a
strictly future finite RFC3339 timestamp. Disabled identities cannot be revived.
Creation yields generation 1, revoked entry, empty tool grants and unbound
services; it does **not** issue any access credential.

Preview returns `preview`, `action`, `expected_generation`, `confirmation_id`,
and `confirmation_expires_at`. No token is generated at preview. Send the same
semantic fields with `preview:false`, `confirm:true`, and `confirmation_id` to
commit. Each handler holds at most 64 pending confirmations, valid for two
minutes. Tickets are handler-bound and consumed before a commit attempt; changed
payloads, replay, stale generation and expired tickets fail. A ticket is not a
replacement for CAS or live expiry/disabled checks.

Success returns `{"applied":true,"entry":{"generation":2,"expires_at":"…","revoked":false}}`.
Issue/rotate additionally return `token` exactly once: 32 cryptographically random
bytes encoded as unpadded base64url. Only its domain-separated digest persists.
No snapshot, audit API or retry endpoint returns that token. Responses use the
existing no-store security headers. Do not log or persist the response in browser
storage. On timeout, disconnect or unknown outcome **do not automatically repeat
issuance**: refresh the snapshot, inspect the generation, then deliberately
preview a new rotation if the delivered credential was lost.

Errors use existing `error` envelopes: malformed request 400, unavailable or
forbidden authority/state 403, CAS/confirmation conflict 409, bounded preview
capacity 429, storage/audit unavailable 503. A storage failure fails the gateway
closed because commit outcome can be uncertain. No credential is returned before
the state and audit transaction commits successfully.

Rotation/revocation invalidates prior entry authentication and handlers, clears
catalogs and best-effort cancels admitted operations. It does not roll back an
already executed downstream side effect. Subsequent discovery is explicit. Policy
version advances with entry mutations to prevent older discovery results from
publishing after the change; tooling should refresh snapshot versions.
