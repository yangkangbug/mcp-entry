# Managed user lifecycle and persistence

Online user creation is a separately authenticated administrative operation, not
self-registration or a role inferred from entry credentials. New identities get
no entry token, no tool grants and no downstream credentials. Creation, issuance,
rotation and revocation require explicit preview and one-time confirmation.
See [admin-api.md](admin-api.md) for the request and recovery contract.

## Compatibility boundary

The schema remains v4. Existing canonical state MAC encoding and the immutable
seed-config topology digest remain byte-for-byte unchanged. Seed users must still
be present and match their configured identities. Managed users are extra
principal rows with a domain-separated identity-derived `managed:` identifier;
the complete rows and bindings are covered by the same authenticated state MAC
and audit checkpoint as seed users. Restore validates shape, identity uniqueness,
entry digest uniqueness and complete bindings before exposing the instance.
Managed users are recovered from authenticated records, never silently merged
from a changed config. An older binary rejects unexpected extra principal rows
rather than silently dropping them. Old v2/v3 stores still require the existing
explicit offline authenticated migration.

All dynamic identities count toward the 64-user bound. Admission and ingress
buckets are added without resetting existing tenant/principal limits. Catalogs
are transient and rebuilt empty. Naturally expired credentials remain stored but
cannot authenticate; expiry does not prevent opening an otherwise valid database.
Revoked, disabled and rotated state survives restart. Binding credentials remain
encrypted under the existing per-binding authenticated encryption format.

## Transaction and uncertainty

The gateway mutex serializes confirmation consumption, current-state CAS,
credential generation, database transaction and publication. Principal state,
audit event and MAC/checkpoint commit together. Only after commit and audit-ring
publication does the handler expose a newly generated token. A write failure
closes the gateway; it never guesses whether retrying issuance would be safe.
Tickets are volatile and lost on restart. A lost success response cannot be
recovered: inspect state and intentionally rotate with a new confirmation.

Entry digests may not equal any currently registered admin authority or other
entry digest. Admin credentials never acquire entry rights. Disabled users have
no implicit re-enable path. Revocation cancels in-flight work best effort; effects
already performed downstream cannot be undone. Synthetic tests exercise lifecycle
and recovery without creating deployable persistent credentials.
