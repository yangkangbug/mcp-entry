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

## Current budgets

These are source-code budgets, not guaranteed elapsed times or additive allowances.
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

Client/proxy timers outside this process must be checked separately. These values
must not be increased merely to make a failing case disappear.

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
