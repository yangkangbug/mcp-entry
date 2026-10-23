# Timeout diagnostics (synthetic baseline)

A `downstream_timeout` is evidence of a timeout, **not a root-cause diagnosis**.
The current failure fields do not distinguish a caller deadline, gateway operation
budget, HTTP client timer, response-header timer, or an upstream/proxy timeout.
No production incident or credential state is established by the loopback tests.

## Collect minimal, redacted evidence first

For one failing attempt, record only what is available and authorized:

- UTC timestamp and approximate elapsed duration; client/gateway build versions.
- Operation kind (discovery or tool call), and a non-secret correlation label.
- Structured `code`, `phase`, `http_status` (if present), and `outcome_unknown`.
- Caller deadline/cancellation state and configured proxy/client timeout budgets.
- Whether connection/headers arrived, whether a complete JSON or SSE result arrived,
  and whether cleanup was attempted; mark unavailable facts as **unknown**.
- Dispatch count and independently confirmed downstream outcome, if safely available.

Do not collect tokens, Authorization/cookie/session headers, endpoint URLs or query
strings, raw SDK errors, request arguments, response bodies, or business results.
Do not infer a missing HTTP status from text inside an error or tool result. A
business `IsError` result is still a received tool result, not a transport failure.
No new logging fields, persistent schema, or API are introduced by this guide.

## Default budgets

These are the legacy defaults, not guaranteed elapsed times or additive allowances.
Earlier parent deadlines win. Transport stages share the operation's remaining time.

| Boundary | Budget | Scope / source |
| --- | --- | --- |
| Caller deadline/cancellation | Caller supplied | Can terminate any remaining operation phase |
| Discovery operation | 5 s | `discover` in `internal/gateway/gateway.go`; includes connection, catalog pages, synchronous cleanup |
| Tool-call operation | 10 s | `Call` in `internal/gateway/gateway.go`; includes admission, connection, call and synchronous cleanup |
| Downstream HTTP client | 12 s | Per HTTP request, including response-body reads; `downstreamOperationClient` |
| DNS resolution | 3 s | `internal/gateway/network_policy.go` |
| Dial | 3 s | Network policy dialer |
| TLS handshake | 3 s | Network policy transport |
| Response headers | 5 s | Network policy transport; not a complete-body deadline |
| Session cleanup | No fresh allowance | Shares operation context; cleanup cannot extend the operation with a new budget |

Client/proxy timers outside this process must be checked separately. Budgets must not be increased merely to make a failing case disappear.

## Controlled per-system budgets

An administrator may opt a fixed system into a bounded profile in local startup
configuration. This is not a tool argument, live update, or retry mechanism:

```json
"timeouts": {
  "discovery_ms": 5000,
  "call_ms": 30000,
  "response_header_ms": 25000
}
```

Omitting `timeouts` preserves all defaults above. If present, all three values
are required integer milliseconds in **1..120000**, and response headers must
not exceed `max(discovery_ms, call_ms)`. Null, empty objects, missing fields,
zero, negative, fractional, unknown fields and out-of-range values are rejected.
Timeout field names must use the exact lowercase spelling shown; duplicate keys
and case aliases are rejected before decoding (including in admin drafts).
Programmatic `System.Timeouts == nil` likewise selects defaults. The 120-second
ceiling is a resource guardrail, **not** a recommended setting or a promise that
an ingress caller/proxy will wait that long.

Discovery and calls have separate total context budgets. In this example a
25-second header ceiling does **not** extend discovery beyond five seconds.
Each request is clipped by the current operation's remaining time and any earlier
parent deadline, including connection negotiation, body reads and synchronous
cleanup. The HTTP client cap is derived as `max(discovery, call) + 2 seconds`
(default 12 seconds, maximum 122 seconds); it never gives a request or cleanup a
fresh operation allowance. DNS, dial and TLS remain capped at three seconds.
No proxy, TLS, IP allowlist, endpoint, authentication or retry policy changes.
A large header budget does not reserve time for the body or cleanup.

Budgets are local runtime settings, excluded from the authenticated identity/
routing topology fingerprint. Existing databases remain readable without a
migration; changing only budgets on restart does not re-import seed credentials,
restore revoked access, or reset audit state. Endpoint, network and authentication
changes still fail topology validation. A configuration draft validates these
fields but does not apply them; edit the authorized startup configuration and
restart the single instance to use a different profile.

## Synthetic five-second boundary evidence

`TestServiceTimeoutRealFiveSecondBoundary` uses the real gateway and default
network transport against loopback fake data. A response withheld for 5.5 seconds
hits the default five-second header timer; the deliberately non-cooperative
handler still completes afterwards. Exactly one call is dispatched, the linked
start/terminal audit retains timeout and `outcome_unknown=true`, and neither
credentials nor endpoint/result canaries appear in the audit. Parallel controls
show the same 5.5-second response succeeds with a per-system 8-second call /
7-second header profile, and succeeds under defaults when headers arrive first
and only the body is delayed. These tests add roughly 5.5 seconds in parallel,
not a 15–21-second real-service probe.

`TestServiceTimeoutDiscoveryClipsLargerHeader` checks a shorter discovery budget
still clips a longer header ceiling. Configuration and restart tests cover bounds,
legacy serialization, and persisted revocation surviving a budget-only change.
`TestServiceTimeoutConfiguredOperationAndCleanup` uses short configured profiles
to verify discovery-body and call-body deadlines, an earlier parent deadline, and
synchronous cleanup sharing the remaining budget without replacing a confirmed
result.
Existing test-only deadline matrices below separately cover parent, operation,
HTTP client, JSON/SSE body and cleanup behavior.

This reproduces a **possible mechanism**, not the root cause of incident #8.
The reported 5.27-second failure is consistent with the five-second header limit,
but lacks independent per-stage tracing; the actual incident cause remains
undetermined. Later downstream completion never changes what was known when the
gateway returned. No real downstream call or production setting was changed.

## Interpret the evidence without overclaiming

1. **Client boundary:** Did the client cancel or exhaust its deadline before a
   complete response? A client timeout alone does not prove gateway/downstream
   cancellation, nor does it establish the tool's outcome.
2. **Connect:** `phase=connect` identifies where failure was classified, including
   protocol negotiation. It does not by itself identify DNS, TCP, TLS or handshake
   as the cause. Failed negotiation probes must not mask the final handshake status.
3. **Discovery:** `phase=discovery` covers catalog work after connection. A slow
   body can fail after successful HTTP headers. No tool call is thereby confirmed.
4. **Call:** Once dispatched, a timeout, disconnect, truncated response, or HTTP
   rejection leaves `outcome_unknown=true` under the conservative contract. HTTP
   408 and 504 map to timeout, but do not prove which machine's timer expired or
   that no side effect occurred. Status omitted/zero means no classified non-2xx
   status is retained, **not** that no HTTP headers were received.
5. **Cleanup:** A complete discovery result or confirmed tool result is preserved
   even if cleanup fails. The implementation does not promise a separately exposed
   cleanup error. Local request release or `Close` returning is not proof that a
   remote session was deleted. Do not label cleanup trouble a failed business call.

Do not blindly retry an unknown-outcome call. First reconcile the effect through
an authorized downstream record or explicit idempotency mechanism. A fresh,
separately authorized read may be appropriate; automatically repeating a write is
not. Never infer expired/revoked credentials from timeout or arbitrary error text.

## Reproduce safely and verify recovery

Use only synthetic loopback servers and fake data; no real endpoints or credentials.

```sh
go test -count=1 ./internal/gateway -run 'TestFailureSDK|TestFailureTransport'
go test -race -count=1 ./internal/gateway -run 'TestFailureSDK|TestFailureTransport'
```

`TestFailureSDKTimeoutBoundaries` independently stalls headers, partial JSON bodies,
and partial SSE bodies. It checks shorter parent and operation deadlines, HTTP
client expiry, and response-header expiry (headers only). Short budgets are local
to the test client/context and do not alter production budgets. Assertions inspect
context state rather than narrow elapsed-time ranges, require exactly one failed
call dispatch, wait for the canceled server handler to exit, and confirm that a
fresh operation succeeds using the same endpoint/client. This is local recovery,
not a proof of remote rollback, production permit accounting, or session deletion.

`TestFailureSDKConnectHTTPStatus` and `TestFailureSDKCallJSONAndSSE` include real
HTTP 408/504 responses, assert typed status retention and conservative outcome
semantics, and prohibit call retries. For non-200 statuses the JSON/SSE matrix
uses the same HTTP error response; it does not claim those errors contain SSE.
Existing cleanup/protocol/contract tests complement these cases with cancellation,
response loss, truncated SSE, cleanup failure and confirmed-result preservation.
Run the complete normal/race suites before accepting a combined change.

For an actual incident, retain this synthetic result separately from the redacted
incident evidence. If timing/source data is absent, record **cause undetermined**
and identify the next authorized observation rather than inventing a cause.
