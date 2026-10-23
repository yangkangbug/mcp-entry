# Client-driven binding: bounded local vertical

Implemented opt-in **synthetic loopback** flow, without a user binding webpage:

1. Start the gateway with `--client-binding` (existing serve options still apply).
   Strong canonical finite entry credentials are required. Remote/TLS listener modes
   are deliberately not enabled for this test surface.
2. The MCP catalogue includes `mcp_entry_connections`, even when no business tool
   can be discovered. It takes only `{}` and returns this identity's configured
   services with at least one currently authorized policy tool. It cannot change
   bindings, choose an identity/endpoint, receive credentials, or contact providers.
3. A user explicitly invokes the trusted local helper, using independently confirmed
   gateway origin and private files. The model never receives those file contents.
4. The dedicated API derives identity from the gateway bearer, checks current entry
   generation, policy, binding generation, and commits via the existing atomic
   persistence/audit path. It then attempts scoped discovery, never a business call.

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

## Exact channel

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
  Errors do not echo request bodies or downstream text. Origins, cookies, fetch-site
  headers, query strings, encoded paths, redirects and GET mutation are rejected.

No automatic retries. If submission response is lost, CLI reports
`outcome_unknown` and instructs checking status before another **explicit** attempt.
A changed generation proves only that a mutation occurred, not that it was this
request (another client may have won). This MVP has no per-request durable receipt
ID/challenge workflow; do not claim exactly-once attribution after a lost response.
The user must resolve conflicting state rather than blindly resubmit. Cancel before
mutation leaves state unchanged; cancel after commit may leave a saved binding.

Both HTTP helper target and API listener are pinned to explicit literal loopback
origins. The helper disables proxying, redirects and replay. HTTPS remote delivery
requires a separately reviewed extension with verified TLS and trusted target
provisioning; never bypass TLS validation to extend this local test mode.

The older `/account` page is unchanged and is not required by this flow. Binding
never changes tool policy, reenables a principal, restores a revoked entry token,
or automatically repeats the user's previously requested business operation.
