# Client-driven binding: bounded local vertical

Implemented opt-in **synthetic loopback** flow with two private submission options:
a [one-time browser connection page](one-time-binding.md) or the existing CLI helper:

1. Start the gateway with `--client-binding` (existing serve options still apply).
   Strong canonical finite entry credentials are required. Remote/TLS listener modes
   are deliberately not enabled for this test surface.
2. The MCP catalogue includes `mcp_entry_connections`, even when no business tool
   can be discovered. It takes only `{}` and returns this identity's configured
   services with at least one currently authorized policy tool. It cannot change
   bindings, choose an identity/endpoint, receive credentials, or contact providers.
3. The agent may request a short-lived link with `mcp_entry_connection_begin`,
   show it to the user, and read its sanitized status with
   `mcp_entry_connection_status`. The user independently verifies the local gateway
   address, authenticates in the page with their own current MCP entry token (not
   an admin token), reviews the verified target, then enters the provider token and
   explicitly confirms. The link alone is not proof of user identity. Alternatively,
   the user invokes the trusted local CLI helper using private files. Neither path
   sends entry/provider secrets through the agent or MCP tool arguments.
4. The dedicated API derives identity from the gateway bearer, checks current entry
   generation, policy, binding generation, and commits via the existing atomic
   persistence/audit path. It then attempts scoped discovery, never a business call.

## Existing CLI helper

Example commands contain **paths and metadata only**, not secrets:

```sh
go run ./cmd/connect --gateway http://127.0.0.1:8080 --entry-file /private/entry --status
go run ./cmd/connect --gateway http://127.0.0.1:8080 --entry-file /private/entry --credential-file /private/provider --service crm --generation 1
```

Files must be regular, owned by the invoking user, owner-only (e.g. mode 0600),
with exact contents and no trailing newline. Entry file is exactly 43 canonical
base64url characters; provider file is at most 4096 printable ASCII bytes, with
no leading/trailing spaces (interior spaces support raw/API-key header values;
provider-specific auth syntax is checked by the gateway). Linux/Darwin helper uses
descriptor-based no-follow traversal: no symlink file or
ancestor is accepted. Use the physical path (e.g. macOS `/private/tmp`, not `/tmp`);
Other platforms compile but private-file access fails closed; Windows credential
submission is not supported. Native desktop client support is **not verified**.
Do not send the files through AI tools or ask an agent to read real credentials.
This is not one-click binding in every MCP client and does not implement OAuth,
refresh tokens, MCP secret form elicitation, or a native client secret plugin.

## Existing CLI HTTP channel

- `GET /binding/api/services`: sanitized `{services:[{system,generation,state,
  discovery_status}],submission,instructions}`. `state` is `missing`, `active`,
  `expired` (only known local expiry), or `revoked` (only local revocation).
  Discovery `available` means currently admitted catalogue entries exist;
  `not_observed` is not a diagnosis of provider health or access.
- `POST /binding/api/credentials`: strict bounded JSON with `service_id`,
  `expected_generation`, `credential`, optional RFC3339 `expires_at`.
  No caller tenant, principal, endpoint or policy field is accepted. This is a
  dedicated HTTP secret submission channel, **not an MCP tool input**.
- Success returns `binding_saved:true`, new sanitized `binding`, and separate
  `discovery_status`: `ready`, `unavailable`, or `not_completed`. A provider 401/403
  or interrupted discovery does not undo the confirmed save or prove local expiry
  or revocation. `ready` does not grant permissions or prove future provider access.
- Save conflict is `version_conflict`; unauthorized configured services are denied.
  Errors do not echo request bodies or downstream text. The CLI channel rejects
  browser Origin/cookie/fetch-site headers, query strings, encoded paths and GET
  mutation; the helper rejects redirects. The separate browser session channel
  instead requires an exact same-origin Origin header.

No automatic retries. If submission response is lost, CLI reports
`outcome_unknown` and instructs checking status before another **explicit** attempt.
A changed generation proves only that a mutation occurred, not that it was this
request (another client may have won). The CLI does not create a connection session
and has no per-request receipt. Its response-loss semantics are unchanged by the
new browser flow: do not claim exactly-once attribution from CLI binding generation.
The user must resolve conflicting state rather than blindly resubmit. Cancel before
mutation leaves state unchanged; cancel after commit may leave a saved binding.

## One-time MCP control tools and browser session

All tools derive the current user from authenticated MCP context. Input objects are
strict: unknown/duplicate fields and secret/identity/endpoint selectors are rejected.
These are metadata-only control tools, not business tools:

- `mcp_entry_connections({})` remains read-only and reports current authorized
  service/binding metadata, including the generation needed by begin.
- `mcp_entry_connection_begin({"service_id":"crm","expected_generation":1})`
  requires exactly those fields: a valid configured service ID (maximum 64
  characters) and an integer generation of at least 1. It returns
  `{session_locator,service_id,expires_at,authorization_url,state:"pending",instructions}`.
  The URL is `/binding/#<session_locator>.<capability>` at the configured trusted
  loopback origin. Both components are random canonical 43-character base64url
  values. Begin creates a session, not a provider binding or business request.
- `mcp_entry_connection_status({"session_locator":"<43-character locator>"})`
  accepts only that locator, not the capability or credentials. It is restricted
  to the owning user with current entry credentials and service authorization.
  The result includes `{session_locator,service_id,state,current_binding,
  save_receipt:"in_memory_session_only",discovery_status,expires_at,
  save_outcome,instructions}`. Only a confirmed save adds `binding_saved:true`
  and `saved_generation`. `save_outcome` is `not_attempted`, `saved`, or `unknown`.
  A consumed session without confirmed save reports `unknown`, not failure.

The browser uses separate same-origin endpoints with the user's independently
entered gateway Bearer, JSON and no cookies:

- `POST /binding/api/session/inspect`: `{session_locator,capability}`; returns
  `{service_id,identity:{tenant,principal},auth_type,expires_at,state:"pending"}`.
- `POST /binding/api/session/confirm`: the same fields plus `credential`,
  `confirm:true`, and optional RFC3339 `expires_at` (the current page does not
  expose this optional field). Successful response is
  `{binding_saved:true,binding,discovery_status}`. Post-save scoped discovery has
  an eight-second budget and reports `ready`, `unavailable`, or `not_completed`.
- `POST /binding/api/session/cancel`: `{session_locator,capability}`; a confirmed
  cancellation returns `{state:"canceled"}`. Local page dismissal does not call
  this endpoint or claim server cancellation.

The capability is bound to user, service, entry generation, policy version,
binding generation and service revision. Confirm consumes it before attempting
commit, so an uncertain commit cannot be replayed using the same link. The server
stores only its digest. Inspect does not consume it. Used, expired, invalidated or
foreign sessions cannot be inspected/confirmed/canceled merely by possessing a URL.

### Receipt lifetime and uncertainty

Sessions live for **five minutes from creation**, with a limit of four per user
and 128 globally. Pending, canceled, consumed and saved sessions share that original
expiry; saving does not extend it. Timer cleanup removes the session and capability
digest. Sessions and receipts are process-memory only and are **not restored after
restart**, even if the underlying binding was durably persisted.

Within that window, a session's confirmed `binding_saved:true` and
`saved_generation` attribute a successful save to that session. They describe the
historical attempt, not the latest binding or current provider usability. The
separate `current_binding` can already differ due to another mutation. A saved
receipt remains separate from discovery status; discovery may still be
`not_observed` while the confirmed save's tool discovery is in progress.

If status is denied/unavailable after expiry, restart, revocation or authorization
change, it does not prove the save failed. Reconcile current binding state and any
conflicts before a new explicit attempt; do not infer ownership of a mutation from
generation alone. There is no durable exactly-once receipt guarantee. Never
resubmit automatically or replay the original business operation. See the
[page lifecycle and unknown-outcome rules](one-time-binding.md) for browser cleanup,
explicit cancellation and verification coverage.

Both HTTP helper target and API listener are pinned to explicit literal loopback
origins. The helper disables proxying, redirects and replay. HTTPS remote delivery
requires a separately reviewed extension with verified TLS and trusted target
provisioning; never bypass TLS validation to extend this local test mode.

The older `/account` page is unchanged and is not required by this flow. Binding
never changes tool policy, reenables a principal, restores a revoked entry token,
or automatically repeats the user's previously requested business operation.
