# One-time connection page (synthetic testing only)

The opt-in `--client-binding` surface adds a user-facing page at `/binding/`.
It does **not** replace `/account`, implement OAuth, or make this nonproduction
gateway safe for real credentials. Use synthetic tokens only. The original HTTP
mode is restricted to a literal-loopback gateway; the opt-in remote mode requires
a fixed, independently trusted HTTPS origin with TLS terminated by this gateway.
See [listener configuration and trust boundaries](client-binding.md#listener-modes-and-trust-boundaries).

## User / agent boundary

1. The agent requests a connection link for an authorized service and current
   binding generation. It may show the returned URL to the user. It must never
   ask the user to paste an entry or provider token into chat or tool arguments.
2. The user independently verifies the browser address. The page immediately
   extracts `#<session_locator>.<capability>` into memory and removes the fragment
   with `history.replaceState`. Neither component is accepted through query fields.
   The page does not automatically send requests on load. Its transport guard
   refuses non-loopback HTTP (including `localhost` names) and non-HTTP(S) pages,
   clears secrets and disables both forms. HTTPS admission is **not** proof that
   a gateway is trustworthy: independently verify the exact origin and certificate
   before entering even synthetic credentials; never bypass certificate warnings.
3. A link is **not identity proof**. The user privately enters their own current
   MCP gateway token, not an administrator token. Explicit verification calls
   `POST /binding/api/session/inspect` with that Bearer and the locator/capability.
   Only after successful verification does the page show the gateway origin,
   tenant/principal, service, credential type and link expiry. The origin shown is
   the actual page origin, not an agent-supplied target. Address verification before
   entering the gateway token remains essential: a page cannot establish its own trust.
4. The user obtains the service credential independently, enters it in the password
   field, checks consent and explicitly saves once. The page sends
   `POST /binding/api/session/confirm` with `{session_locator, capability,
   credential, confirm:true}` and the verified gateway Bearer. It offers no
   editable identity, endpoint, header, policy or service-target field and never
   retrieves an existing secret.
5. A confirmed `binding_saved:true` is distinct from discovery status (`ready`,
   `unavailable`, `not_completed`). Discovery can attempt tool listing; it never
   automatically retries the original business operation. Even completed discovery
   does not expand authorization or guarantee future provider availability.
   The user/agent must decide any subsequent business operation separately.

All three browser API calls (inspect, confirm, cancel) are same-origin POSTs with
JSON, no cookies, no redirects, no referrer, and `cache:no-store`. The server also
validates origin and the current entry/session/binding authorization. Tokens are
not placed in query strings, browser storage or third-party requests. Both secret
inputs use `type=password`, `autocomplete=off`, and no spellcheck. Browser/password
manager behavior is not a guarantee of secure memory erasure.

## Dismissal, expiry and uncertain outcomes

- **Clear and end this page** only clears local state; it does not claim server
  cancellation. A server link can remain valid until expiry. After successful
  inspection a separate **Cancel this link** action explicitly calls the cancel
  API once, clears local state and distinguishes confirmed versus unknown cancellation.
- Page hide, offline, or dismissal clears secret references, password inputs,
  displayed identity and consent. Pending operations are aborted best-effort.
  Aborting does not roll back a server commit. An epoch invalidates late responses,
  including delayed JSON bodies, so they cannot restore a dismissed page.
- Reload/back restoration cannot resume from a persisted token: no secret state is
  stored. The consumed fragment is not retained by the page. A user may still have
  the original link in their chat/history; expiry and server checks remain necessary.
- Rejected, expired, used, conflicting or malformed flows stop, clear local secrets,
  and direct the user to check status / request a new link. Permission and session
  failures may deliberately share a server error to avoid revealing session existence.
- A lost/malformed save response or interrupted save is **outcome unknown**, never
  assumed failure. There are no automatic retries. Ask the agent to query the
  session/connection status before deciding on a new explicit attempt. Saving does
  not mean discovery or business execution succeeded. Never replay a business
  request automatically as a side effect of authorization.

## Verification

Run `node --check internal/gateway/binding_assets/binding.js` and
`node tests/client-binding/frontend.test.cjs`. CI includes both. The dependency-free
Node DOM tests cover fragment stripping and fail-closed URLs, rejection of remote
HTTP and non-HTTP(S), HTTPS admission and IPv4/IPv6 loopback regressions, no load-time network,
independent authentication before target display, explicit consent, duplicate-click
suppression, request shape/privacy options, success versus discovery, clear/offline/
pagehide, late JSON responses, invalid responses, unknown saves and explicit cancel.

These are state/DOM tests, **not actual browser isolation or visual QA**. Actual
browser verification is paused for this work; no user computer was used. CSP,
origin enforcement, session expiry and capability binding require the separate Go
backend/security tests. The old account page and admin core are unchanged.
