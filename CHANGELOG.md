## 0.5.0

- **Manifests gain a monotonic `publishCounter`** — the freshness arbitration
  a stale manifest read lacked. Wire-visible only when > 0 (unbumped fleets
  stay byte-identical, golden-pinned); publishers bump once per publish event
  via `GroupService.bumpedForPublish`; `decryptManifest` gains
  `minPublishCounter` and refuses a manifest below the caller's persisted
  high-water mark under EVERY charter policy. Closes the replayed
  pre-rotation manifest restoring a removed member and rolling the group key
  back to one they still hold; the counter arbitrates rollback, not
  divergence (equal-counter concurrent publishes remain last-write-wins).
  SPEC.md's manifest shape, check table, and threat model updated to match.
- **Ownership transfers are retry-safe.** `transferOwnershipWithCharter` had
  a publish-retry trap: a repeat call with the already-updated group minted a
  self-link or a link not signed by the previous owner — permanently invalid
  under `validateCharter`, which under a strict policy stopped every member's
  manifest from decrypting. Both transfer variants are now idempotent no-ops
  when the target already owns the group, and the charter builder validates
  its own extended chain before returning (a retryable `StateError` instead
  of a silently poisoned link). No wire/crypto change — the guards only
  constrain what the builder emits.

## 0.4.0

Adopter-portability release (the seams a consuming app needs to swap its own
group models/service out for this package's). All additive; defaults are
byte- and behavior-identical to 0.3.0, so existing consumers see no change.

- **Unknown-field passthrough**: `Group.extra` (wire-visible — re-emitted by
  `toManifestJson()`, so a package-based republish can't silently drop an
  adopter's manifest field) and `GroupMember.extra` (local-only — re-emitted by
  `toJson()` only, never published). Captured by `fromJson`; recognized keys
  can never be shadowed or fabricated by the bag; an empty bag serializes to
  nothing. Both `copyWith`s take `extra:` (replaces the bag; omit a key to
  clear it).
- **`CharterPolicy` on `decryptManifest`** (default `strict` — today's exact
  behavior). Opt-in `tolerant` treats a charter-authority failure exactly as
  `charter == null` (fall back to trusting the caller-supplied
  `ownerPublicKey`) while keeping the groupId pin, key-length check, and
  roster uid↔key vetting fully strict. For adopters with legacy/diverged
  charters still draining out of their fleet; the usurpation tradeoff is
  pinned in the adversarial suite as documented behavior. See SPEC.md.
- **`GroupMember.copyWith(clearAvatarPhotoPath: true)`** — resets the local
  photo override to null (the `?? this` idiom can't), mirroring the existing
  `clearCharter`.
- **Legacy `'emoji'` key fallback** in `GroupMember.fromJson` — read into
  `avatarEmoji` (which wins when both are present), consumed rather than
  passed through, and migrated to `avatarEmoji` on the next write. For
  on-device JSON written before the rename.
- Requires `identity` 0.3.0 (`IdentityStore.clear()` failure surfacing).

## 0.3.0

- Requires `identity` 0.2.0: `Identity.seed` is now a `SecureKey`, so the
  charter-signing derivations run against locked memory. No call-site change
  here — `createGroup`/`transferOwnershipWithCharter` pass `identity.seed`
  straight through.
- `decryptManifest` now DROPS a roster entry that fails the uid↔key binding
  instead of rejecting the whole manifest. An unbound entry is never trusted
  either way, but rejecting outright let one corrupt or schema-drifted member
  block every other member's sync indefinitely. (Availability parity with the
  origin app's native invite finalizers, which already tolerated this.)
- `encryptManifestFor` uses `encryptBlobWithBoxDisposing`, so the derived DH
  key is wiped on the throw path too.

## 0.2.0

- **Security: removed the `idBinding:"legacy"` charter binding.** It skipped
  hash-binding, so anyone could self-sign a genesis naming any groupId and
  validate as its owner. Every group is now self-certifying. `backfillCharter`
  is removed with it; groups predating charters stay un-chartered.
- **`decryptManifest` now validates instead of merely decrypting**: requires a
  caller-pinned `expectedGroupId`, treats a present charter as authoritative
  (tip uid must match `ownerUid`, tip box key must be the sender's), supports a
  `minCharterHeight` anti-rollback high-water mark, checks roster uid↔key
  binding, and returns null rather than throwing. **Breaking**: signature and
  nullable return.
- **`addMember` enforces uid↔box-key binding** and throws `ArgumentError` on a
  mismatch. **Breaking** for callers constructing synthetic members.
- Charter validation is now strict on untrusted input: exact payload schema,
  integer-typed version/timestamps within JS-safe bounds, ASCII-only strings —
  required for byte-parity with a JS verifier.
- Self-links and non-increasing timestamps are rejected, making the chain
  `height` a trustworthy monotonic ownership epoch.
- `transferOwnership` throws instead of asserting (asserts are stripped in
  release); `transferOwnershipWithCharter` refuses to silently produce an
  unenforceable group without `allowUnchartedFallback: true`.
- Hostile-input hardening: `unsealKey` returns null on non-decodable sealed
  content, `Group.tryFromJson` for untrusted manifests, charters capped at 256
  entries, `Group.copyWith(clearCharter: true)`.
- Tests 24 → 61, adding one case per charter rejection path and the manifest
  boundary attacks.

## 0.1.0

- Initial extraction from a shipped production app.
- Generic `Group` / `GroupMember` models, the generic `GroupService` methods
  (create / add / remove+rotate / transfer / manifest DH crypto / group-key blob
  crypto), and the signed ownership charter (genesis + transfer links + validator).
- App domain payload methods dropped in favour of the generic
  `encryptWithGroupKey` / `decryptWithGroupKey` seam.
- Charter signing domain lifted to a `signingKeyDomain` parameter (was hardcoded).
- Depends on the `identity` package for crypto primitives + `Identity`.
