# Schema execution isolation — feasibility design, not shipped support

Status: synthetic local prototype, 2026-10-23. **The gateway still validates in
process.** This is a proposal for later review, not integrated support or a changed
shipping contract. No production edits, real credentials, network requests, host
settings, installed software, or downstream systems were used for this prototype.

Recovery provenance: after the workspace reverted to an older snapshot, the prior
prototype, design document, and `/tmp/schema-resource-assess` were absent at 05:15
UTC. These files were **reconstructed from the agent's visible conversation/tool
context**, not recovered byte-for-byte. The admission fixture was freshly copied
from the surviving `internal/gateway/schema_policy.go` (package renamed to main).
No inaccessible session files were read. Tests and vet were rerun on the
reconstructed files; the results below are from that new run.

## Why budgets alone are insufficient

The current admission fixture accepts an object property `v` with 32 `anyOf`
branches, each `pattern: a{1000}b`. A value of 60,000 `a` characters yields a
784-byte schema, 60,008-byte instance, and estimated work 34. The earlier assessment
resolved it in about 2.5 ms but killed validation after 11 CPU seconds without a
result. That older measurement is historical context, not newly rerun here.
This is expensive repeated linear regex work, not a catastrophic-backtracking
claim about Go's regex engine.

In the reviewed gateway snapshot, validation occurs before the downstream call
context/limiter. Context cancellation alone cannot interrupt synchronous regex
validation. Structural budgets are still valuable but cannot guarantee execution
time. Admission and compilation need isolation too, not only `Resolved.Validate`.

## Proposed design: disposable one-shot helper, not a pool

Launch a trusted helper directly, without a shell. Set a deadline before launch,
use a separate bounded validation semaphore, and reject saturation without an
unbounded queue. On timeout or caller cancellation, kill the child, wait/reap it,
then release capacity. No retained schema cache, request state, or pool recovery
protocol is required. The prototype's 300 ms budget and capacity one are test
parameters, not proposed production defaults.

Packaging requires an explicit decision:

* CLI: a private self-helper argument may enter a minimal path before config,
  credentials/store, logging, gateway, or network initialization. Package init
  functions still run; audit them before adopting self-exec.
* Embedded library: the host's executable need not implement this protocol.
  Require an explicit trusted absolute helper path/launcher with a matching
  protocol version. Do not silently self-exec an arbitrary host or fall back to
  in-process validation. Choose fail-closed startup/discovery/call semantics.

Send only immutable selected schema bytes and normalized argument bytes, not the
whole catalog, identities, credentials, headers, or configuration. Preserve the
full schema, including `$schema`, `$defs`, `definitions`, and `$ref`; do not flatten
it. Run policy checks, decoding, compile/resolve, and validation inside the child,
with external schema loading disabled. Discovery also needs a compile-only request
under the same lifetime/capacity limits. Recompilation on each call is an intentional
initial simplicity/latency tradeoff, subject to measurement.

## Bounded IPC, error classes, and lifecycle

Prototype request: 12-byte header (`SV01`, two big-endian lengths), then at most
128 KiB schema and 64 KiB instance. These are prototype protocol limits, not new
shipping acceptance limits. Response: exactly 8 bytes (`SR01`, status, three zero
bytes). The parent retains only 8 bytes, flags extra data, drains/discards excess,
and rejects unknown, truncated, malformed, or extra output. stderr is discarded,
not logged. Raw validator text, schema paths/expressions, and instance values
cannot enter response errors through this protocol.

Classes: OK, invalid instance, compile rejection, protocol error, timeout,
canceled, busy, launch failure, and crash. Production public/audit mapping remains
to be reviewed. Timeout is not proof of semantic invalidity. Never expose raw
child error messages.

The child environment is explicitly replaced with only `GOMAXPROCS=1`; no parent
environment is inherited. No extra file descriptors are passed; use a neutral
working directory. A fake canary verifies the full child environment without
reading real credentials. This prevents accidental inheritance, but **is not an
OS security sandbox**: same-user filesystem/network access is not revoked.

No descendants are allowed. `CommandContext` kills the direct child, not a portable
process tree. `WaitDelay` bounds pipe-copy cleanup, not descendants' lifetimes.
Adding subprocesses requires platform process-group/job-object containment or an
explicit unsupported deployment decision. A practical wall-clock kill is not an
exact real-time guarantee under scheduler starvation or unkillable kernel I/O.
Keep capacity occupied until wait finishes; do not claim recovery while a child
may still be alive.

## Dispatch and revocation

Capture selected schema and authorization/generation snapshot under the gateway
lock, then validate outside the lock. All helper/admission failures must produce
zero downstream calls. After successful validation, reacquire the final dispatch
lock shared with revocation and recheck operation authorization, selected tool
identity, catalog generation, policy version, and context. Only then acquire
downstream capacity, start audit, obtain credentials, and dispatch. Preserve the
existing post-validation fence; do not move it before validation. Discovery
publication needs its own post-compilation generation/policy fence. Separate
validation capacity is essential because downstream limits begin too late.
Fairness and whole-call deadline composition require integration decisions.

## Reconstructed prototype evidence

Files: `.tools/schema-isolation/{main.go,main_test.go,policy.go,go.mod}`. The folder
is covered by the repository's `.tools/` ignore rule. It is a standalone module,
not imported by production code. Offline reproduction with bundled dependencies:

```sh
cd .tools/schema-isolation
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
  GOCACHE=/workspace/shared/mcp-entry/.tools/gocache \
  ../go/bin/go test -v -count=1 -timeout=20s .
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
  GOCACHE=/workspace/shared/mcp-entry/.tools/gocache ../go/bin/go vet .
```

Both passed after reconstruction. The fixture was explicitly rechecked against
admission: 784-byte schema, 60,008-byte instance, work 34. Three pathological child
executions timed out at 301.34, 303.57, and 301.64 ms, were waited/reaped, released
capacity, and each was followed by successful normal validation. Cancellation of
a sleeping synthetic helper reaped in 1.04 ms. Saturation returned busy.

Tests also passed: clean child environment, crash, short reply, 1 MiB output flood
with fixed parent buffer, oversized input, missing executable, compile rejection,
instance rejection, and intact `$defs` references. A synthetic dispatch harness
rejected invalid/timeout inputs and concurrent generation/policy changes with zero
dispatch, then dispatched one valid request. **This is not a gateway integration
test.**

## Not established; gates before shipping

* No production wiring, compile-only opcode, full policy parity, audit mapping,
  explicit library launcher API, or deployment packaging. The helper does not
  reproduce every production type/dialect check.
* Compilation occurs inside the killable child, but no naturally slow compilation
  fixture was demonstrated. Generic hung-helper cancellation was tested.
* No hard portable memory/CPU limits were established. A child may allocate enough
  to affect the host before its deadline. Go memory limits are soft, not a hard
  resource guarantee. rlimits/cgroups/job objects and deployment budgets need
  platform-specific design/authorization; none were changed here.
* Need platform matrix, executable trust/integrity, descendant containment,
  startup/exit benchmarks, fairness/load/leak testing, integrated zero-downstream
  and revocation tests, exact rejection/audit accounting, discovery publication
  cancellation, and shutdown/reap coverage.
* Preserve source-schema immutability and all existing dialect/reference behavior;
  do not silently rewrite advertised schemas or narrow supported features.

Next step is packaging/failure-semantics review, not claiming integrated support.
Any eventual implementation should be narrowly scoped and separately reviewed.
