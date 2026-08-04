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
