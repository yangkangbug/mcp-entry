# Offline storage maintenance

These operations are for the trusted local owner of a single-instance synthetic
gateway. They are not remote administration endpoints, a production key-management
service, an OAuth issuer, or a high-availability protocol. No real account keys
are provisioned by these examples.

## Before every maintenance session

1. Stop the server and wait for shutdown. The SQLite store has one exclusive owner;
   do not run maintenance alongside a serving process or another operator.
2. Use a trusted private directory on a local filesystem supporting SQLite locking
   and synchronization. Keep database, configuration, exports, and secret files
   inaccessible to other users. Do not remove SQLite journals or override locks.
3. Take a cold backup after a clean close. Keep its matching external root key
   separately, with restricted access. A database backup alone is insufficient.
4. Retain the matching topology configuration. Reopening authenticates persisted
   state; editing configuration is not a way to restore revoked access or reset
   credentials. Do not use `-init-db` for recovery or maintenance.

Examples assume a built `./bin/gateway`, a private synthetic configuration, and
existing private files. Paths and identifiers are illustrative. Supply secrets
through files, never literal command-line arguments, shell history, logs, or the
repository. `-key-file` accepts exactly 32 raw bytes in a private regular,
non-symlink file; `-key-stdin` is an alternative requiring exactly 32 raw bytes and
EOF. Neither accepts a hexadecimal or base64 representation of the root key.

Maintenance uses `OpenMaintenance`, opens no HTTP listener, and does not call
`Refresh` or contact downstream systems. Entry changes, migration, key rotation,
and archive retention require this offline mode. Missing, corrupt, mismatched,
wrong-key, or unsupported state fails closed, without in-memory fallback.

## Explicit migration to v4

Normal serving rejects legacy v2/v3 stores. Stop the old server, retain a cold
backup and its separate key, then explicitly migrate with the existing key:

```sh
./bin/gateway -config private/config.json -db private/state.db \
  -key-file private/root.key -operation migrate
```

Only authenticated v2 and v3 stores are upgraded to v4; other legacy versions are
not supported. An already-current v4 store needs no conversion. Migration retains
persisted policies, credentials, binding state, and expiries rather than importing
replacement state from configuration. It creates entry generation 1 and records
the migration in the authenticated audit journal. Existing indefinite entry
expiries are not silently shortened. Migrated entries are conservatively marked
as not strong: replace them offline with fresh finite-lived credentials before
using remote-test or account-page modes requiring strong entry authentication.

Reopen and inspect status before restarting. Do not treat an error or missing
command output as proof that migration did not commit.

## Inspect, replace, or revoke entry credentials

Read the current identity status first:

```sh
./bin/gateway -config private/config.json -db private/state.db \
  -key-file private/root.key -operation status -tenant demo -principal alice
```

`Entry` contains `Generation`, `ExpiresAt`, and `Revoked`, never the credential or
its verification digest. Use that entry generation as `-expected-version` for
entry mutations. It is distinct from a policy version or a binding generation.
Both replacement and revocation advance the entry generation; stale expectations
fail with a conflict instead of overwriting newer state.

Prepare a fresh cryptographically random 32-byte token externally, encoded as
canonical unpadded base64url. The private regular, non-symlink entry file must
contain exactly 43 encoded bytes, with no newline, whitespace, or padding. Select
an explicit finite future RFC3339 expiry. The following variables contain only a
generation number and a timestamp, not secret material:

```sh
./bin/gateway -config private/config.json -db private/state.db \
  -key-file private/root.key -operation replace-entry -tenant demo -principal alice \
  -expected-version "$ENTRY_GENERATION" -entry-file private/next-entry.token \
  -entry-expires "$ENTRY_EXPIRY"
```

Replacement invalidates the previous entry credential. To revoke without issuing
another credential, read status again and use its current generation:

```sh
./bin/gateway -config private/config.json -db private/state.db \
  -key-file private/root.key -operation revoke-entry -tenant demo -principal alice \
  -expected-version "$ENTRY_GENERATION"
```

Reopen status to confirm the resulting generation and state. Never automatically
retry a mutation after a storage error, output failure, or lost response. The
client must inspect actual persisted state before deciding what to do next.

## Rotate the external root key

Prepare a different externally generated random key in a new private regular,
non-symlink file containing exactly 32 raw bytes. Do not overwrite or discard the
old key file during the operation:

```sh
./bin/gateway -config private/config.json -db private/state.db \
  -key-file private/root.key -operation rotate-key -new-key-file private/next-root.key
```

Rotation transactionally re-encrypts stored downstream credentials, updates state
integrity protection, and authenticates retained audit history under the new key.
It does not issue new entry tokens or replace downstream credentials. Historical
audit identifiers remain stable. The CLI reports success only after closing and
successfully reopening the database with the new key. Update the next server
invocation to use that verified new key.

A commit or verification error can mean the new state reached disk. Keep the
server stopped, preserve both external keys securely, and reopen with the
new key first, then the old key if needed, one at a time, to establish which
authenticated state exists.
Preserve diagnostic evidence without logging key material. If neither opens,
stop and investigate; do not initialize or overwrite the database. Keep historical
keys needed for retained backups and archives separately from those artifacts.

## Audit export and explicit retention

Use the global offline view to include storage-maintenance events:

```sh
./bin/gateway -config private/config.json -db private/state.db \
  -key-file private/root.key -operation audit-all -after-sequence 0 -limit 100
```

`-limit` is 1–1000. Continue with the last returned event sequence as the exclusive
cursor. Identity-scoped `-operation audit -tenant demo -principal alice` also
returns audit status. An unfinished start has an unknown outcome, not evidence of
failure or permission to retry a downstream operation.

The persistent journal is bounded and does not silently delete records when
full. Explicit archival exports retained events before pruning; read-only audit
pagination alone does not free capacity. Inspect the current last sequence and
pass it as the archive expectation:

```sh
./bin/gateway -config private/config.json -db private/state.db \
  -key-file private/root.key -operation archive-audit \
  -archive-file private/audit-export-001.json -expected-version "$LAST_SEQUENCE"
```

The destination must be a new file in a trusted private directory. Archive export
uses exclusive creation with mode 0600, synchronizes the file and parent directory,
and verifies the exported bytes before any pruning. One database transaction
then records an authenticated base checkpoint and export hash, prunes covered
rows, and appends an archive event. Sequences remain monotonic; they do not reset
to zero. Stale expectations and live pending operations prevent archival. Durable
orphan starts left by a crash are exported verbatim with an unknown outcome;
archiving them does not turn them into successes, failures, or permission to retry.
The cumulative `ArchivedUnfinished` count is retained in the authenticated
checkpoint and audit status, so clearing retained rows does not erase that warning.
Audit status `Unfinished` includes both archived unknown outcomes and current
unmatched starts; `ArchivedUnfinished` identifies the archived portion.

Keep every archive, its verification key, and the reported export hash. Root key
rotation does not rewrite external archives. A failed export can leave a partial
file; a later database failure can leave a complete export without pruning. Never
overwrite or discard that evidence on retry. An uncertain checkpoint commit
requires reopening and inspecting authenticated state before deciding whether
pruning committed. Do not infer completion merely from an export file existing.

## Recovery limits

The authenticated chain and state manifest detect inconsistent edits, not rollback
of an entire valid historical database. Restoring an old backup can resurrect
revoked credentials or permissions. Never blindly restore a backup after an
uncertain commit; determine current state and reconcile later revocations first.
A cold backup is recovery evidence, not proof that it is safe to serve.

Keep the service stopped until the database, matching key, entry generations,
revocations, and audit checkpoint have been verified. This implementation has no
external freshness witness, distributed ownership, automatic business retry, or
automatic safe backup-restore workflow.
