# groups

[![CI](https://github.com/needyaz/groups/actions/workflows/ci.yml/badge.svg)](https://github.com/needyaz/groups/actions/workflows/ci.yml)

End-to-end-encrypted group membership: models, key rotation, per-member
encrypted manifests, and a signed ownership charter. This package is the
group-membership logic that shipped in a production app, extracted in
place.

This is the L1 layer: it builds on the [`identity`](https://github.com/needyaz/identity) package and has
no domain coupling — it knows about groups, members, keys, manifests, and
ownership, but not about what payloads ride inside the group key.

## Design

This layer targets small, owner-administered groups — a family, a shared
folder, a handful of people who all know who started the group.

What it defends against:

- **The server.** The server (or any storage/transport) never sees plaintext:
  not the payloads, not the roster, not the group key. Manifests are encrypted
  per-member with DH(owner, member); payloads ride under the 32-byte group key.
  A server can withhold or delay data (availability is not defended), but it
  cannot read or undetectably alter it.
- **Non-members.** Without a member's secret key there is nothing to decrypt.
- **Removed members, going forward.** `removeMember` always rotates the group
  key — unconditionally, even when the uid wasn't present — so an ex-member
  cannot read anything encrypted after their removal. What they already
  received while a member is theirs; no protocol can un-share it.
- **Ownership usurpation.** The signed charter (genesis + transfer links) means
  a server or member cannot install a new owner: each transfer must be signed
  by the outgoing owner's Ed25519 key, the genesis is self-certifying (the
  groupId *is* the hash of the genesis payload), and every entry's owner uid is
  bound to its box key by the same SHA-256 derivation `identity` uses.
- **Ownership rollback.** The validated chain height is a monotonic epoch: a
  client that persists a high-water mark can refuse a shorter — but still
  validly signed — historical chain replayed by a malicious server.

What it deliberately trusts:

- **The owner.** The owner mints and distributes the group key and publishes
  the roster. A malicious owner can admit anyone, and can in principle show
  different members different rosters — there is no cross-member transcript
  consistency check. The owner is inside the trust boundary: they invited
  everyone and control membership anyway.
- **Local charter enforcement is fail-open.** For a locally held group, a
  missing or invalid charter yields no enforcement — a corrupted charter
  doesn't destroy access to data, and groups created before charters existed
  have none. This does not apply at the manifest boundary: when an incoming
  manifest carries a charter, it is authoritative, and anything short of a
  full match is rejected, since fail-open there would let a member disable
  enforcement by claiming ownership. (`decryptManifest`'s opt-in
  `CharterPolicy.tolerant` extends the local fail-open posture to the boundary
  for adopters whose fleet still carries legacy/diverged charters — a
  documented, transitional downgrade; the default stays strict. See SPEC.md.)

What it does not provide:

- **Forward secrecy within an epoch** — the group key changes on removal, not
  per message. One leaked group key reads everything encrypted under it until
  the next rotation.
- **Post-compromise security** — recovering from a silent member-device
  compromise requires removing that member (which rotates the key).
- **Roster consistency proofs, deniability, or metadata privacy.**

### Comparison to MLS

[MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420) is the standardized
protocol for group key agreement: ratchet-tree key agreement with no trusted
distributor, per-epoch forward secrecy and post-compromise security, and
transcript-hash roster consistency. It fits large or admin-hostile groups.
This layer targets a narrower case, and each MLS guarantee has a
corresponding cost here:

- MLS removes the trusted key distributor. Here the owner is inside the trust
  boundary by definition, so that machinery would defend against a party
  already trusted.
- MLS requires a delivery service providing a totally ordered handshake
  stream to all members. This stack has no ordered broadcast channel —
  manifests are eventually-consistent blobs — and building one would be a
  larger system than this entire layer.
- MLS implementations are large and subtle, and there is no production-grade
  Dart implementation as of this writing. This layer is ~1,250 lines of pure
  Dart, and its ownership-charter validator is checked byte-for-byte against
  an independent server-side reimplementation via a shared golden vector.

For large or member-administered groups, or a threat model that includes the
group's own administrator, use MLS. For small groups with a trusted owner,
this is a smaller, narrower protocol that documents the trade explicitly.

## What's in here

- **`group.dart`** — `Group` + `GroupMember` models, with a split between the
  encrypted **manifest** (server/peers) and **local-only** fields (avatars,
  local labels). App-specific membership flags belong in the app layer, not here.
- **`group_service.dart`** — the generic operations:
  - `createGroup` — mint a group + its self-certifying ownership charter
  - `addMember` (idempotent; enforces uid↔key binding) / `removeMember`
    (always rotates the group key)
  - `transferOwnership` / `transferOwnershipWithCharter`
  - `encryptManifestFor` / `decryptManifest` — per-member DH manifest crypto;
    the decrypt side is the trust boundary and validates the incoming
    manifest rather than simply decrypting it (see SPEC)
  - `encryptWithGroupKey` / `decryptWithGroupKey` — the seam for app payloads
- **`ownership_charter.dart`** — the signed delegation chain (genesis +
  transfer links), the deterministic group-id derivation, and the pure
  `validateCharter` validator mirrored by a server-side verifier.

## Usage

```dart
import 'package:groups/groups.dart'; // also re-exports `identity`

final sodium = await SodiumInit.init();

final group = GroupService.createGroup(
  sodium: sodium,
  name: 'Family',
  identity: myIdentity,
  signingKeyDomain: myIdentityConfig.signingKeyDomain,
);

// Encrypt an app payload for the group:
final blob = GroupService.encryptWithGroupKey(
  sodium: sodium, data: item.toJson(), groupKey: group.groupKey,
);
```

The charter-minting methods take `signingKeyDomain` — the per-app Ed25519
domain from your `IdentityConfig`. Everything else is pure data/crypto.

Receiving a manifest is the one place hostile input enters, so it is pinned and
validated by the caller's own expectations, and returns null rather than
throwing:

```dart
final group = GroupService.decryptManifest(
  sodium: sodium,
  blob: blob,
  myIdentity: me,
  ownerPublicKey: senderKey,
  expectedGroupId: knownGroupId,   // pin: rejects a manifest for another group
  minCharterHeight: storedHeight,  // anti-rollback high-water mark
);
if (group == null) return; // do not trust it
```

## Verifying this works

`identity` is a git dependency (`ref: main`, no tags yet — see
[`identity`'s CLAUDE.md](https://github.com/needyaz/identity/blob/main/CLAUDE.md)),
so `dart pub get` fetches it directly.

Prereqs: the Dart SDK.

```
dart pub get
dart test
```

Expect `All tests passed!` — 77 tests across three files:

- **`group_model_test.dart`** (18) — `Group`/`GroupMember` JSON round-trips,
  the manifest-vs-local-storage field split, the unknown-field passthrough
  rules (wire-visible `Group.extra` vs local-only `GroupMember.extra`;
  recognized keys can never be shadowed), the `publishCounter`
  omitted-at-zero/round-trip golden, and the `GroupRole` golden test
  (a pure-member roster serializes byte-for-byte unchanged, proving the
  role-only-when-non-default backward-compat rule holds).
- **`group_service_test.dart`** (28) — the full lifecycle against the real
  crypto end to end (create → add → remove/rotate → manifest round-trip →
  transfer → roles → sealed keys → group-key blobs), plus the adversarial
  boundary cases: a roster entry whose uid doesn't match its box key, a
  manifest naming a different group, a member-published manifest usurping
  ownership, a replayed pre-transfer charter, a stale manifest below the
  publish-counter high-water mark, retry-idempotent/self-validating
  ownership transfers, and tampered / truncated / garbage / wrong-recipient
  blobs — all of which are refused, not thrown on.
- **`ownership_charter_test.dart`** (31) — the golden-vector parity anchor
  (a fixed, pre-signed chain that must validate to owner uid `90ad2339…` here
  and in the server-side verifier; if it goes red, canonical-JSON bytes,
  SHA-256, or Ed25519 verification has drifted between the two languages),
  plus one test per rejection path: forged genesis and link signatures,
  cross-group grafts, hash-binding forgery, spliced `prevHash`, self-links,
  non-increasing timestamps, the removed `legacy` binding, float/oversized
  integers (the cross-language parity trap), and schema violations — plus the
  `charterEnforcedOwner` fail-open/high-water-mark behavior for local
  enforcement decisions.

```
dart analyze
```

Expect `No issues found!`.

### Test coverage

The lifecycle tests prove the generic operations (create/add/remove/transfer/
manifest crypto/group-key blobs) work end to end against real libsodium, not
mocks. The adversarial tests prove the protocol rejects what it should: every
documented rejection path is exercised with input an attacker could actually
produce, including forged signatures. The charter golden vector proves this
package's `validateCharter` and an independent reimplementation in another
language agree byte-for-byte on the same signed input — the same claim
`identity`'s cross-language vectors make, scoped to the ownership layer.

What it does not prove: the golden vector was generated by this
implementation's own lineage rather than by an independent one, so it locks
drift between the two verifiers, not the correctness of the format itself.
Regenerating it from an independently-implemented signer (as `identity`'s
derivation vectors now are) is tracked work.

## Known gaps

- **Manifest freshness is opt-in.** The manifest carries a monotonic
  `publishCounter` (omitted at zero — unbumped fleets stay byte-identical);
  publishers bump via `GroupService.bumpedForPublish`, consumers persist a
  per-group high-water mark and pass `minPublishCounter` to
  `decryptManifest`. A replayed pre-rotation manifest is then refused. Until
  a fleet adopts both halves it keeps the old exposure, and the counter
  arbitrates rollback, not divergence (equal-counter concurrent publishes
  remain last-write-wins).
- **The charter golden vector is not independently generated** (see above).
- **No roster-consistency proof**: a malicious owner can in principle show
  different members different rosters. See Design above.

## License

MIT — see [LICENSE](LICENSE). No third-party code is vendored into this repo;
everything below is consumed as an unmodified dependency.

Third-party licenses (relevant when redistributing built apps, since their
binaries embed these — preserve the upstream notices):

| Dependency | Used by | License |
|---|---|---|
| [`identity`](https://github.com/needyaz/identity) | foundation: identity, key derivation, crypto primitives | MIT |
| [libsodium](https://github.com/jedisct1/libsodium) | all crypto (via `sodium`) | ISC |
| [`sodium`](https://pub.dev/packages/sodium) (Dart bindings) | libsodium types + group-key generation | BSD-3-Clause |
| [`crypto`](https://pub.dev/packages/crypto) | SHA-256 for charter hashing | BSD-3-Clause |
| [`bip39`](https://pub.dev/packages/bip39) | transitive via `identity` | BSD-3-Clause |

`identity`'s optional native crypto mirrors (`native/ios/`, `native/android/`)
carry additional notices (swift-sodium ISC, lazysodium-android MPL-2.0 as a
`libsodium.so` delivery vehicle only, Gradle wrapper Apache-2.0) — see that
repo's License section; they apply only to apps that ship those mirrors.
