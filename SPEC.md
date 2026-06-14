# groups — specification

The end-to-end-encrypted group-membership protocol. Builds on
[`identity`](../identity); depends on its primitives + byte-parity rules.

## Data model

**GroupMember**: `uid`, `publicKeyB64` (X25519 box key), `edPubKeyB64` (Ed25519
charter key, learned from peers), `displayName`, plus local-only `localDisplayName`,
`avatarEmoji`, `avatarPhotoPath`, `avatarPlain`.

**Group**: `groupId`, `name`, `ownerUid`, `members[]`, `groupKey` (32-byte
symmetric), `createdAt`, `manifestUpdatedAt` (local-only), `charter`.

Two JSON shapes:
- `toManifestJson()` — server/peers. Excludes local-only fields; `groupKey` is
  base64; includes `charter`.
- `toJson()` — local storage. Manifest fields + local-only fields.

## Group key

32 random bytes. Encrypts everything an app shares in the group. **Rotated on
every member removal** (`removeMember` always mints a fresh key, even if the uid
wasn't present). Never transmitted in plaintext.

## Manifest distribution

The owner publishes one manifest per member: `encryptBlobWithBox(group.toManifestJson(),
DH(ownerSecret, memberPublic))`. A member decrypts with `DH(mySecret, ownerPublic)`
to learn the roster **and the group key**. This is how the key reaches members.

## The app-payload seam

`encryptWithGroupKey(data, groupKey)` / `decryptWithGroupKey` = `crypto_secretbox`
with the group key, wire format `base64(nonce ‖ ciphertext)`. This is the *only*
place an app's domain data touches `groups` — the layer never knows what's inside.

## Ownership charter

A signed delegation chain proving who owns a group, carried in the manifest so it
rehydrates into a blank DB. Wire shape:

```
[ { "payload": {…}, "sig": "<base64 Ed25519>" }, … ]
```

- **genesis** payload: `{v:1, type:"genesis", groupId, ownerUid, ownerEdPubKey,
  ownerBoxPubKey, createdAt, nonce, idBinding}`. Signed by the owner's own Ed25519
  key. `idBinding:"hash"` → `groupId = SHA-256(canonicalJson({v, ownerEdPubKey,
  ownerBoxPubKey, createdAt, nonce}))` (self-certifying; un-forgeable for a given
  id). `idBinding:"legacy"` → groupId is a pre-existing UUID (forgeable; treat as
  fill-blank-only on claim).
- **link** payload: `{v:1, type:"link", groupId, ownerUid, ownerEdPubKey,
  ownerBoxPubKey, prevHash, ts}`. Signed by the **previous** (outgoing) owner's
  key. `prevHash = SHA-256(canonicalJson(prevEntry))`.

`validateCharter(chain, expectedGroupId)` checks, per entry: version, groupId
match, `uid == SHA-256(boxPub)[0..15]`, signature (genesis by self, links by prior
owner), hash-binding for the genesis, prevHash continuity. Returns the tip owner +
`hashBound`. Pure, deterministic, mirrored byte-for-byte by the Deno
`claim-group` verifier.

`charterEnforcedOwnerKey()` returns the box key incoming manifests must
authenticate against — or null (no enforcement) when there's no charter, it's
invalid, or its tip diverged from `ownerUid`.

The three charter-minting `GroupService` methods take `signingKeyDomain` (from the
app's `IdentityConfig`) — never hardcoded.

## Golden vector (parity lock)

Charter `[{genesis…}]` with owner uid `90ad2339401503c0a5645621a9bd89cb` and
groupId `4bbfb814115b252bfcf5f65122d92bf8cf500f4e06b28c71a6276b2b341b0f29`
validates in both `test/ownership_charter_test.dart` (Dart) and the vault's
`charter_parity_test.ts` (Deno). If either side rejects it, parity is broken.

## Out of scope (deliberately app-local)

No realtime/transport/streams, no `isPaused`/`sharingMode`, no location/place/
session payloads. Those live in the app.
