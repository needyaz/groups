# CLAUDE.md — groups

Guidance for Claude Code when working in this package.

## What this is

`groups` is the **L1 shared substrate** for end-to-end-encrypted group
membership across the Luci apps: the `Group`/`GroupMember` models, the generic
`GroupService` operations (create, add, remove + key rotation, ownership
transfer, per-member manifest DH crypto, and group-key blob crypto), and the
signed **ownership charter** (genesis + transfer links + validator).

Extracted from Mylo (`models/group.dart`, `services/group_service.dart`,
`crypto/ownership_charter.dart`); the crypto is byte-identical to that source.
It depends on [`identity`](../identity) and has **no domain coupling** — it knows
about groups, members, keys, manifests, and ownership, but not about what rides
inside the group key.

## Dependency direction

```
app (vault / mylo)  →  groups  →  identity
```

Nothing here may import an app. `groups` is a path dependency (like `sammy`).

## The key seam: `encryptWithGroupKey` / `decryptWithGroupKey`

This is where an app's own payloads ride. Mylo puts `LocationPayload`/`Place`
through it; Vault puts `VaultItem` through it. **Do not add domain-specific
methods here** (no `encryptGroupLocation`, no `encryptItems`) — those belong in
the app's own service. Keep this layer payload-agnostic.

## Byte-parity: the charter

`ownership_charter.dart` is mirrored by a Deno `claim-group` verifier. Canonical
JSON bytes + SHA-256 + Ed25519 verification must agree byte-for-byte across Dart
and Deno. `ownership_charter_test.dart` pins the shared **golden vector**; if it
goes red, parity is broken. The three charter-minting `GroupService` methods take
`signingKeyDomain` (from the app's `IdentityConfig`) — they never hardcode it.

## What was deliberately dropped

Mylo's `Group` carried `isPaused` and `sharingMode` (location-sharing
semantics). Those are **not** here — they belong in the app layer. Likewise the
location/place/share-session/event encrypt wrappers were replaced by the single
generic `encryptWithGroupKey` pair. Keep the model and service generic; resist
re-adding app concepts.

## Conventions

- Models keep a clean split: `toManifestJson()` (server/peers, no local-only
  fields) vs `toJson()` (local storage, includes avatars/local labels).
- `removeMember` **always** rotates the group key, even if the uid wasn't found.
- Pure data + crypto only; no I/O, no network, no streams. (Realtime/transport
  is intentionally app-local — see the Mylo extraction notes.)

## Testing

`flutter test` — model serialization, full group lifecycle (create → add →
remove+rotate → manifest DH round-trip → ownership transfer), group-key blob
crypto, and the charter golden-vector parity anchor. `flutter analyze` clean.
Every change gets a test.

## Docs & commits

- `SPEC.md` — the full group/manifest/charter protocol (wire formats, validation
  rules, golden vector). `README.md` — usage.
- **Never mention Claude, AI, or any assistant in commit messages, PR/issue
  text, or anywhere in git history** — no `Co-Authored-By`, no "generated with"
  trailers. Write commits as a plain human author.
- Work on `main` (no feature branches). Commit only when explicitly asked.
