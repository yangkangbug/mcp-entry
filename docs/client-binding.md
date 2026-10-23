# Client-driven binding: bounded synthetic vertical

Implemented opt-in **synthetic testing** flow with a
[one-time browser connection page](one-time-binding.md) on literal-loopback HTTP
or explicitly configured direct TLS. The existing private-file CLI helper remains
**HTTP literal-loopback only**:

1. Start the gateway with `--client-binding` (existing serve options still apply).
   Strong canonical finite entry credentials are required. Remote browser testing
   requires all the direct-TLS flags and trust prerequisites below.
2. The MCP catalogue includes `mcp_entry_connections`, even when no business tool
   can be discovered. It takes only `{}` and returns this identity's configured
   services with at least one currently authorized policy tool. It cannot change
   bindings, choose an identity/endpoint, receive credentials, or contact providers.
3. The agent may request a short-lived link with `mcp_entry_connection_begin`,
   show it to the user, and read its sanitized status with
   `mcp_entry_connection_status`. The user independently verifies the gateway
   address, authenticates in the page with their own current MCP entry token (not
   an admin token), reviews the verified target, then enters the provider token and
   explicitly confirms. The link alone is not proof of user identity. Alternatively,
   the user invokes the trusted local CLI helper using private files. Neither path
   sends entry/provider secrets through the agent or MCP tool arguments.
4. The dedicated API derives identity from the gateway bearer, checks current entry
   generation, policy, binding generation, and commits via the existing atomic
   persistence/audit path. It then attempts scoped discovery, never a business call.

## Listener modes and trust boundaries

The default remains `--client-binding` on an HTTP literal-loopback listener.
Remote browser sessions require **all** of `--client-binding`,
`--allow-remote-test`, `--binding-public-origin`, `--tls-cert` and `--tls-key`.
`--binding-public-origin` is a fixed HTTPS origin (scheme + host + optional port),
not a page URL: do not include userinfo, a path, query or fragment. Use a concrete
reachable DNS name or IP, not a wildcard bind address. This is the external origin
users actually visit; `--listen` is the process-local bind address. Layer-4 TLS
passthrough or port mapping can make their ports differ, provided the external
origin routes to this gateway's TLS listener without terminating TLS elsewhere.
The public origin's host must match the certificate SAN (DNS SAN for a name, IP
SAN for an IP). The program does not verify network routing or reachability.
Provision the origin and certificate trust independently of the agent link.

Illustrative **synthetic-only** configuration (paths and metadata, no secrets):

```sh
go run ./cmd/gateway --config /private/synthetic-config.json \
  --listen 0.0.0.0:8443 --client-binding --allow-remote-test \
  --binding-public-origin https://gateway.test:8443 \
  --tls-cert /private/gateway-test.crt --tls-key /private/gateway-test.key
```

This example assumes `gateway.test` is deliberately resolved to the test gateway,
the certificate contains `DNS:gateway.test` in its SAN, and its issuing test CA is
trusted by the test browser/client. Supply strong, canonical, finite synthetic
entry credentials in the configuration; this is not a way to expose demo tokens.
Keep the test private and restrict network access. Do not use real accounts or
production secrets, disable TLS verification, or click through certificate warnings.
Certificate loading/name checks do not establish browser trust or endpoint ownership.

The gateway itself terminates TLS. Reverse-proxy TLS termination is **not supported**;
`Host`, `Forwarded` and `X-Forwarded-*` never provision or select the public origin.
Browser requests must match the configured origin/authority and arrive over direct
TLS. `--allow-insecure-http-test` does not enable remote client binding. Existing
admin/account restrictions remain unchanged; this does not publish those surfaces.

`HTTPSClientBindingHandler` exposes only the page/assets and browser session APIs
(`inspect`, `confirm`, `cancel`). It does **not** expose the old direct CLI routes
`/binding/api/services` or `/binding/api/credentials`. The local HTTP handler keeps
those routes; `cmd/connect` is not extended to remote HTTPS. MCP control tools remain
metadata-only and generate links using the fixed configured origin, never a request
header. Remote delivery changes neither authorization scope nor receipt lifetime,
and does not run or replay the user's original business operation.

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
  literal-loopback origin, or the explicitly configured HTTPS public origin. Both components are random canonical 43-character base64url
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

The HTTP helper target and legacy direct CLI API remain pinned to explicit literal
loopback origins. The helper disables proxying, redirects and replay. Only the
one-time browser session surface supports the opt-in direct-TLS mode described
above; this is a bounded synthetic extension, not production readiness, OAuth, or
verified native support across MCP clients.

The older `/account` page is unchanged and is not required by this flow. Binding
never changes tool policy, reenables a principal, restores a revoked entry token,
or automatically repeats the user's previously requested business operation.
