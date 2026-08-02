# groups

End-to-end-encrypted group membership: models, key rotation, per-member
encrypted manifests, and a signed ownership charter. Extracted from a shipped
production app; the crypto is byte-identical to that source.

This is the L1 layer: it builds on the [`identity`](../identity) package and has
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
  ownership.

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
  production-grade Dart implementation. This layer is ~850 lines that two
  independent implementations (Dart + the server-side verifier) check
  byte-for-byte against golden vectors.

If your groups are large, member-administered, or your threat model includes
the group's own administrator, use MLS — this library is the wrong tool. For
small groups with a definitionally-trusted owner, this is the same trade
made honestly and in the open.

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

Expect `All tests passed!` — 61 tests across three files:

- **`group_model_test.dart`** (11) — `Group`/`GroupMember` JSON round-trips,
  the manifest-vs-local-storage field split, and the `GroupRole` golden test
  (a pure-member roster serializes byte-for-byte unchanged, proving the
  role-only-when-non-default backward-compat rule holds).
- **`group_service_test.dart`** (24) — the full lifecycle against the REAL
  crypto end to end (create → add → remove/rotate → manifest round-trip →
  transfer → roles → sealed keys → group-key blobs), **plus the adversarial
  boundary cases**: a roster entry whose uid doesn't match its box key, a
  manifest naming a different group, a member-published manifest usurping
  ownership, a replayed pre-transfer charter, and tampered / truncated /
  garbage / wrong-recipient blobs — all of which must be refused, not thrown on.
- **`ownership_charter_test.dart`** (26) — the **golden-vector parity anchor**
  (a fixed, pre-signed chain that must validate to owner uid `90ad2339…` here
  and in the server-side verifier; if it goes red, canonical-JSON bytes,
  SHA-256, or Ed25519 verification has drifted between the two languages),
  plus one test per rejection path: forged genesis and link signatures,
  cross-group grafts, hash-binding forgery, spliced `prevHash`, self-links,
  non-increasing timestamps, the removed `legacy` binding, float/oversized
  integers (the cross-language parity trap), and schema violations.

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

MIT — see [LICENSE](LICENSE). No third-party code is vendored into this repo.

This package's only dependency is [`identity`](../identity) (MIT), which in turn
brings libsodium (ISC) and its Dart bindings plus BSD-3-Clause Dart packages —
see that repo's License section for the full table and the notice obligations
that apply when redistributing built apps.
