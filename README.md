# groups

Shared end-to-end-encrypted group membership for Luci apps. Extracted from Mylo
(`models/group.dart`, `services/group_service.dart`, `crypto/ownership_charter.dart`).
The crypto is byte-identical to that source.

This is the L1 layer: it builds on the [`identity`](../identity) package and has
**no domain coupling** — it knows about groups, members, keys, manifests, and
ownership, but not about what payloads ride inside the group key.

## What's in here

- **`group.dart`** — `Group` + `GroupMember` models, with a clean split between
  the encrypted **manifest** (server/peers) and **local-only** fields (avatars,
  local labels). Location-domain flags (`isPaused`, `sharingMode`) were dropped —
  they belong in the app layer.
- **`group_service.dart`** — the generic operations:
  - `createGroup` / `backfillCharter` — mint a group + signed ownership charter
  - `addMember` (idempotent) / `removeMember` (rotates the group key)
  - `transferOwnership` / `transferOwnershipWithCharter`
  - `encryptManifestFor` / `decryptManifest` — per-member DH manifest crypto
  - `encryptWithGroupKey` / `decryptWithGroupKey` — **the seam for app payloads**
    (a vault encrypts its items here; Mylo encrypted locations/places here)
- **`ownership_charter.dart`** — the signed delegation chain (genesis +
  transfer links), the deterministic group-id derivation, and the pure
  `validateCharter` validator mirrored by a Deno `claim-group` verifier.

## Usage

```dart
import 'package:groups/groups.dart'; // also re-exports `identity`

final sodium = await SodiumInit.init();

final group = GroupService.createGroup(
  sodium: sodium,
  name: 'Family',
  identity: myIdentity,
  signingKeyDomain: vaultIdentity.signingKeyDomain, // from IdentityConfig
);

// Encrypt an app payload for the group:
final blob = GroupService.encryptWithGroupKey(
  sodium: sodium, data: item.toJson(), groupKey: group.groupKey,
);
```

The three charter-minting methods take `signingKeyDomain` — the per-app Ed25519
domain from your `IdentityConfig`. Everything else is pure data/crypto.

## Layering note

`groups` depends on `identity`, which is a Flutter package (it bundles
secure-storage). So `groups` is currently a Flutter package even though its own
code is pure Dart. If a pure-Dart (server/CLI) consumer is ever needed, split
`identity` into a pure `identity_core` (crypto + identity) and a Flutter
`identity` (storage), and point `groups` at the core.

## Verifying this works

Anyone with a clean checkout can reproduce this — no Mylo checkout, no
backend, no account needed. One extra step vs. a normal standalone repo,
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

Expect `All tests passed!` — 24 tests across three files:

- **`group_model_test.dart`** (11) — `Group`/`GroupMember` JSON round-trips,
  the manifest-vs-local-storage field split, and the `GroupRole` golden test
  (a pure-member roster serializes byte-for-byte unchanged, proving the
  role-only-when-non-default backward-compat rule holds).
- **`group_service_test.dart`** (8) — the full group lifecycle exercised
  against the REAL crypto end to end: create (mints a hash-bound,
  self-validating charter) → add member (idempotent) → remove member (rotates
  the group key) → manifest DH encrypt/decrypt round-trips between owner and
  member → ownership transfer appends a valid charter link → `setRole` →
  `sealKeyForMember`/`unsealKey` round-trip → `encryptWithGroupKey`/
  `decryptWithGroupKey` round-trip.
- **`ownership_charter_test.dart`** (5) — a freshly-built genesis validates
  and is hash-bound, **plus the golden-vector parity anchor**: a fixed,
  pre-signed charter chain (`_vectorJson`, hardcoded in the test) must
  validate to the exact same owner uid (`90ad2339...`) here as it does in
  Mylo's Dart suite and the vault's Deno `claim-group` verifier
  (`supabase/prod/tests/*.ts`). If this one goes red, canonical-JSON bytes,
  SHA-256, or Ed25519 verification has drifted between the two languages —
  that's a parity break, not a test flake.

```
flutter analyze
```

Expect `No issues found!`.

### What "all green" proves

The lifecycle test proves the generic operations (create/add/remove/transfer/
manifest crypto/group-key blobs) work end to end against real libsodium, not
mocks. The charter golden vector proves this package's `validateCharter` and
Deno's independent reimplementation agree byte-for-byte on the same signed
input — the same claim `identity`'s cross-language vectors make, scoped to
the charter/ownership layer instead of the raw crypto primitives.
