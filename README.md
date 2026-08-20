# groups

[![CI](https://github.com/needyaz/groups/actions/workflows/ci.yml/badge.svg)](https://github.com/needyaz/groups/actions/workflows/ci.yml)

End-to-end-encrypted group membership: models, key rotation, per-member
encrypted manifests, and a signed ownership charter. Extracted from a shipped
production app; the crypto is byte-identical to that source.

This is the L1 layer: it builds on the [`identity`](https://github.com/needyaz/identity) package and has
**no domain coupling** — it knows about groups, members, keys, manifests, and
ownership, but not about what payloads ride inside the group key.

## Why this exists — threat model, and why not MLS

This layer is a deliberately small protocol for **small, owner-administered
groups** — a family, a shared folder, a handful of people who all know who
started the group. That design point, stated up front, is what makes the rest
of the trade-offs coherent.

### What it defends against

- **The server.** The server (or any storage/transport) never sees plaintext:
  not the payloads, not the roster, not the group key. Manifests are encrypted
  per-member with DH(owner, member); payloads ride under the 32-byte group key.
  A server can withhold or delay data (availability is not defended), but it
  cannot read or undetectably alter it.
- **Non-members.** Without a member's secret key there is nothing to decrypt.
- **Removed members, going forward.** `removeMember` always rotates the group
  key — unconditionally, even when the uid wasn't present — so an ex-member
  cannot read anything encrypted after their removal. (What they already
  received while a member is theirs forever; no protocol can un-share it.)
- **Ownership usurpation.** The signed charter (genesis + transfer links) means
  a server or member cannot install a new owner: each transfer must be signed
  by the outgoing owner's Ed25519 key, the genesis is self-certifying (the
  groupId *is* the hash of the genesis payload), and every entry's owner uid is
  bound to its box key by the same SHA-256 derivation `identity` uses.
- **Ownership rollback.** The validated chain height is a monotonic epoch: a
  client that persists a high-water mark can refuse a shorter — but still
  validly signed — historical chain replayed by a malicious server.

### What it deliberately trusts

- **The owner.** The owner mints and distributes the group key and publishes
  the roster. A malicious owner can admit anyone, and can in principle show
  different members different rosters (there is no cross-member transcript
  consistency). This is not an oversight: in an owner-administered group the
  owner is *definitionally* inside the trust boundary — they invited everyone
  and control membership anyway.
- **Local charter enforcement is fail-open by design.** For a *locally held*
  group, a missing or invalid charter yields no enforcement rather than a
  bricked group — a corrupted charter shouldn't destroy access to data, and
  groups created before charters existed have none. Note this does **not**
  apply at the manifest boundary: when an incoming manifest carries a charter,
  it is authoritative and anything short of a full match is rejected, because
  there "fall open" would let a member disable enforcement by simply claiming
  ownership. (`decryptManifest`'s opt-in `CharterPolicy.tolerant` extends the
  local fail-open posture to the boundary for adopters whose fleet still
  carries legacy/diverged charters — a documented, transitional downgrade;
  the default stays strict. See SPEC.md.)

### What it does not provide

- **Forward secrecy within an epoch** — the group key changes on removal, not
  per message. One leaked group key reads everything encrypted under it until
  the next rotation.
- **Post-compromise security** — recovering from a silent member-device
  compromise requires removing that member (which rotates the key).
- **Roster consistency proofs, deniability, or metadata privacy.**

### Why not MLS?

[MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420) is the standardized
answer to group key agreement, and for large or admin-hostile groups it is the
right one: ratchet-tree key agreement with no trusted distributor, per-epoch
forward secrecy and post-compromise security, and transcript-hash roster
consistency. We chose not to use it because every one of those guarantees
solves a threat outside this design point, and each carries real cost:

- MLS removes the trusted key distributor — but here the owner is *inside* the
  trust boundary by definition, so that machinery defends against a party we
  already trust.
- MLS requires a **delivery service** providing a totally ordered handshake
  stream to all members. This stack has no ordered broadcast channel —
  manifests are eventually-consistent blobs — and building one is a larger
  system than this entire layer.
- MLS implementations are large, subtle, and (as of this writing) there is no
  production-grade Dart implementation. This layer is ~1,250 lines of pure
  Dart, and its ownership-charter validator is checked byte-for-byte against
  an independent server-side reimplementation via a shared golden vector.

If your groups are large, member-administered, or your threat model includes
the group's own administrator, use MLS — this library is the wrong tool. For
small groups with a definitionally-trusted owner, this is the same trade
made honestly and in the open.

## Why this is public

Same reason as [`identity`](https://github.com/needyaz/identity), and not primarily for reuse. This
layer is where the group-encryption claims of the apps built on it are kept
or broken — who can read what, what a removal actually revokes, what the
server can and cannot do. Publishing it turns the threat model above from a
marketing paragraph into a checkable artifact: the adversarial tests and the
charter golden vector run on any clean checkout, and the gaps are listed by
us under "Known gaps" rather than discovered by someone else.

It is MIT-licensed and genuinely adoptable — the `CharterPolicy` and
config seams exist for exactly that — but read it first as a statement of
how we build: state the design point, defend it, test every rejection path
with input an attacker could actually produce, and write down what is *not*
provided next to what is.

## What's in here

- **`group.dart`** — `Group` + `GroupMember` models, with a clean split between
  the encrypted **manifest** (server/peers) and **local-only** fields (avatars,
  local labels). App-specific membership flags belong in the app layer, not here.
- **`group_service.dart`** — the generic operations:
  - `createGroup` — mint a group + its self-certifying ownership charter
  - `addMember` (idempotent; enforces uid↔key binding) / `removeMember`
    (always rotates the group key)
  - `transferOwnership` / `transferOwnershipWithCharter`
  - `encryptManifestFor` / `decryptManifest` — per-member DH manifest crypto;
    the decrypt side is the **trust boundary** and validates rather than merely
    decrypting (see SPEC)
  - `encryptWithGroupKey` / `decryptWithGroupKey` — **the seam for app payloads**
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

## Layering note

`groups` depends on `identity`, which is a Flutter package (it bundles
secure-storage). So `groups` is currently a Flutter package even though its own
code is pure Dart. If a pure-Dart (server/CLI) consumer is ever needed, split
`identity` into a pure `identity_core` (crypto + identity) and a Flutter
`identity` (storage), and point `groups` at the core.

## Verifying this works

Anyone with a clean checkout can reproduce this — no backend, no account
needed. One extra step vs. a normal standalone repo,
though:

> **`identity` must be cloned as a sibling directory.** `groups` depends on
> it via a local **path** dependency (`identity: {path: ../identity}` in
> `pubspec.yaml`), not a git/pub dependency — so `flutter pub get` fails with
> a "Content-Length" / path-not-found error unless `../identity` (relative to
> this repo) already exists. This is a known gap for an outside clone, not
> yet fixed — tracked to become a git dependency later so `groups` is
> clone-and-go standalone. For now:
>
> ```
> git clone https://github.com/needyaz/identity.git
> git clone https://github.com/needyaz/groups.git
> # the two must be siblings on disk:
> #   some-dir/identity/
> #   some-dir/groups/
> cd groups
> ```

Prereqs: Flutter SDK.

```
flutter pub get
flutter test
```

Expect `All tests passed!` — 75 tests across three files:

- **`group_model_test.dart`** (17) — `Group`/`GroupMember` JSON round-trips,
  the manifest-vs-local-storage field split, the unknown-field passthrough
  rules (wire-visible `Group.extra` vs local-only `GroupMember.extra`;
  recognized keys can never be shadowed), and the `GroupRole` golden test
  (a pure-member roster serializes byte-for-byte unchanged, proving the
  role-only-when-non-default backward-compat rule holds).
- **`group_service_test.dart`** (24) — the full lifecycle against the REAL
  crypto end to end (create → add → remove/rotate → manifest round-trip →
  transfer → roles → sealed keys → group-key blobs), **plus the adversarial
  boundary cases**: a roster entry whose uid doesn't match its box key, a
  manifest naming a different group, a member-published manifest usurping
  ownership, a replayed pre-transfer charter, and tampered / truncated /
  garbage / wrong-recipient blobs — all of which must be refused, not thrown on.
- **`ownership_charter_test.dart`** (31) — the **golden-vector parity anchor**
  (a fixed, pre-signed chain that must validate to owner uid `90ad2339…` here
  and in the server-side verifier; if it goes red, canonical-JSON bytes,
  SHA-256, or Ed25519 verification has drifted between the two languages),
  plus one test per rejection path: forged genesis and link signatures,
  cross-group grafts, hash-binding forgery, spliced `prevHash`, self-links,
  non-increasing timestamps, the removed `legacy` binding, float/oversized
  integers (the cross-language parity trap), and schema violations — and the
  `charterEnforcedOwner` fail-open/high-water-mark behavior for local
  enforcement decisions.

```
flutter analyze
```

Expect `No issues found!`.

### What "all green" proves

Three distinct claims. The lifecycle tests prove the generic operations
(create/add/remove/transfer/manifest crypto/group-key blobs) work end to end
against real libsodium, not mocks. The adversarial tests prove the protocol
*rejects* what it should: every documented rejection path is exercised with
input an attacker could actually produce, including forged signatures — which
matters, because a validator whose happy path works tells you nothing about
whether it can be bypassed. And the charter golden vector proves this package's
`validateCharter` and an independent reimplementation in another language agree
byte-for-byte on the same signed input — the same claim `identity`'s
cross-language vectors make, scoped to the ownership layer.

What it does **not** prove: the golden vector was generated by this
implementation's own lineage rather than by an independent one, so it locks
*drift* between the two verifiers, not the correctness of the format itself.
Regenerating it from an independently-implemented signer (as `identity`'s
derivation vectors now are) is tracked work.

## Known gaps

Stated plainly rather than left for a reader to find:

- **Manifests carry no freshness field.** Nothing in `toManifestJson()` is
  monotonic, so a replayed pre-rotation manifest — validly signed by the owner,
  no forgery needed — is indistinguishable from a current one and can put
  members back on a key a removed member still holds. Closing this properly
  means adding a key epoch to the manifest, which is a wire change. Until then
  a transport that can replay must carry its own sequencing.
- **The charter golden vector is not independently generated** (see above).
- **No roster-consistency proof**: a malicious owner can in principle show
  different members different rosters. See the threat model.

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
| [`bip39`](https://pub.dev/packages/bip39), [`flutter_secure_storage`](https://pub.dev/packages/flutter_secure_storage) | transitive via `identity` | BSD-3-Clause |

`identity`'s optional native crypto mirrors (`native/ios/`, `native/android/`)
carry additional notices (swift-sodium ISC, lazysodium-android MPL-2.0 as a
`libsodium.so` delivery vehicle only, Gradle wrapper Apache-2.0) — see that
repo's License section; they apply only to apps that ship those mirrors.
