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

## Tests

`flutter test` — model serialization, full group lifecycle (create → add →
remove+rotate → manifest DH round-trip → ownership transfer), group-key blob
crypto, and the charter golden-vector parity anchor shared with Mylo + Deno.
