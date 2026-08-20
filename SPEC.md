# groups — specification

The end-to-end-encrypted group-membership protocol. Builds on
[`identity`](https://github.com/needyaz/identity); depends on its primitives +
byte-parity rules.

## Data model

**GroupMember**: `uid`, `publicKeyB64` (X25519 box key), `edPubKeyB64` (Ed25519
charter key, learned from peers), `displayName`, plus local-only `localDisplayName`,
`avatarEmoji`, `avatarPhotoPath`, `avatarPlain`.

**Group**: `groupId`, `name`, `ownerUid`, `members[]`, `groupKey` (32-byte
symmetric), `createdAt`, `manifestUpdatedAt` (local-only), `publishCounter`
(wire-visible, serialized only when > 0 — see *Manifest freshness* below),
`charter`.

Two JSON shapes:
- `toManifestJson()` — server/peers. Excludes local-only fields; `groupKey` is
  base64; includes `charter`.
- `toJson()` — local storage. Manifest fields + local-only fields.

**Unknown-field passthrough (`extra`)**: `fromJson` captures any key it does not
recognize into an opaque `extra` map, so an adopter's app-specific fields
survive a round-trip through these models without the package knowing what they
mean. The two models re-emit deliberately differently:

- `Group.extra` is **wire-visible** — re-emitted by `toManifestJson()` (a
  package-based republish must not silently drop an adopter's manifest field,
  e.g. a group-level sharing mode; dropping one can silently revert a member's
  chosen privacy posture fleet-wide). Never put local-only data here.
- `GroupMember.extra` is **local-only** — re-emitted by `toJson()` only, never
  by `toManifestJson()`; unrecognized per-member keys must not silently ride
  the wire.

An `extra` entry can never shadow or fabricate a recognized key (recognized
keys always win at serialization, and `fromJson` never captures them), and an
empty map serializes to nothing — output is byte-identical to a
pre-passthrough client.

## Group key

32 random bytes. Encrypts everything an app shares in the group. **Rotated on
every member removal** (`removeMember` always mints a fresh key, even if the uid
wasn't present). Never transmitted in plaintext.

## Manifest distribution

The owner publishes one manifest per member: `encryptBlobWithBox(group.toManifestJson(),
DH(ownerSecret, memberPublic))`. A member decrypts with `DH(mySecret, ownerPublic)`
to learn the roster **and the group key**. This is how the key reaches members.

`decryptManifest` is the package's trust boundary — every byte reaching it is
peer-authored — so it validates rather than merely decrypting, and returns null
(never throws) on any failure:

| check | why |
|---|---|
| `groupId == expectedGroupId` (caller-pinned) | a peer whose DH key you hold can otherwise hand you a manifest naming a *different* group, and a caller upserting by returned id replaces its view of that group |
| charter validates for that groupId | a manifest carrying an unvalidatable chain is not trustworthy |
| charter tip uid `==` manifest `ownerUid` | divergence is the usurpation attack, not a reason to relax |
| charter tip box key `==` the sending owner's key | only the charter's owner may publish |
| `height >= minCharterHeight` (caller high-water mark) | rejects a replayed older chain |
| `publishCounter >= minPublishCounter` (caller high-water mark) | rejects a replayed older MANIFEST: charter height only moves on ownership transfers, so without this a re-served pre-rotation manifest silently restores a removed member and rolls the group key back to one they still hold. Enforced under **every** charter policy — it is caller-provided arbitration like the `groupId` pin, not charter trust |
| `groupKey` is 32 bytes; every roster entry's `uid == uidForBoxPublicKey(its key)` | see *Roster binding* |

When a group has **no** charter there is nothing to enforce and only the
structural checks apply. When it *has* one, the charter is authoritative:
anything short of a full match is a rejection. (This is deliberately stricter
than `charterEnforcedOwner`, which fails open on tip divergence for local
enforcement decisions — at the manifest boundary that fail-open would let a
member switch enforcement off simply by claiming ownership.)

**`charterPolicy`** (default `CharterPolicy.strict`): `strict` is the behavior
above. `tolerant` is an explicit, opt-in escape hatch for adopters whose fleet
contains groups whose charters legitimately cannot validate (legacy
un-hash-bound charters still draining out; an uncharted ownership transfer's
permanently diverged tip) and for whom a hard rejection means those groups
never sync again. Under `tolerant`, a charter-authority failure is treated
exactly as `charter == null` — trust falls back to the caller-supplied
`ownerPublicKey` — while every other check in the table (groupId pin, key
length, roster binding) stays fully strict. This knowingly re-opens the
usurpation hole for affected groups (the adversarial suite pins that tradeoff
as documented behavior); it is transitional, and adopters should return to
`strict` once such groups are gone. Adopters whose every group is chartered
must stay on the default.

## Roster binding

A `(uid, publicKeyB64)` pair from an untrusted source is only accepted when
`uid == uidForBoxPublicKey(publicKey)` — the same derivation `identity` uses.
Without this, a roster entry can name Alice while carrying Mallory's key, and
everything addressed "to Alice" (sealed item keys, manifests) encrypts to
Mallory while the UI shows Alice. Enforced by `addMember` (throws) and by
`decryptManifest` (rejects the manifest).

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
  key. `idBinding` **must** be `"hash"`: `groupId = SHA-256(canonicalJson({v,
  ownerEdPubKey, ownerBoxPubKey, createdAt, nonce}))`. Every group is therefore
  self-certifying — the id *is* the hash of its genesis, so no competing genesis
  can be minted for an existing group.
- **link** payload: `{v:1, type:"link", groupId, ownerUid, ownerEdPubKey,
  ownerBoxPubKey, prevHash, ts}`. Signed by the **previous** (outgoing) owner's
  key. `prevHash = SHA-256(canonicalJson(prevEntry))`.

> **Removed: `idBinding:"legacy"`.** It skipped the hash-binding check, so anyone
> could self-sign a genesis naming *any* groupId and validate as its owner — and
> because the result was indistinguishable from a genuine charter, it made the
> group look protected while being trivially forgeable. There is no builder for
> it and `validateCharter` rejects it (`genesis_not_hash_bound`). Groups created
> before charters simply stay un-chartered (unenforced, as they already are);
> they gain protection only by being recreated.

`validateCharter(chain, expectedGroupId)` is pure, deterministic, and mirrored
byte-for-byte by the server-side verifier. Per entry it checks:

1. **Schema** — exactly `{payload, sig}`; the payload's key set exactly matches
   the set for its `type`; no missing or extra fields (an extra field would ride
   under the signature while being ignored by validation).
2. **Types** — `v` and the timestamp are `int` (not `1.0`), timestamps within
   `[0, 2^53-1]`, every other field an ASCII `String`. **This is load-bearing for
   cross-language parity, not hygiene**: `{"v":1.0}` compares equal to `1` in
   Dart but canonicalizes to `1.0` there and `1` in JS, so a lax check lets a
   chain verify in one verifier and fail in the other. Same for integers beyond
   JS's safe range.
3. **Binding** — `groupId == expectedGroupId` on every entry (so a link cannot
   be grafted from another group's chain); `ownerUid == SHA-256(ownerBoxPub)[0..15]`.
4. **Signatures** — genesis by its own key; each link by the **prior** owner's key.
5. **Chain** — genesis first, `prevHash` continuity, **no self-links** (an
   `ownerUid` equal to the previous owner's), strictly increasing timestamps.
6. **Size** — at most `kMaxCharterEntries` (256) entries, refused before any
   crypto, since a charter rides inside a manifest and is re-validated repeatedly.

Returns `{valid, reason, owner, height}`. `height` (genesis = 1, +1 per accepted
link) is a **monotonic ownership epoch**: persist the greatest value ever seen
and pass it as `minHeight`/`minCharterHeight` to refuse a shorter — but still
validly signed — chain replayed to roll ownership back. The self-link ban is what
makes that comparison meaningful: without it, a past owner could pre-sign an
arbitrarily long fork of no-op self-links and beat the legitimate chain.

`charterEnforcedOwnerKey()` / `charterEnforcedOwner()` return the box key
incoming manifests must authenticate against (the latter also returns `height`
so a caller can advance its high-water mark) — or null, meaning *no enforcement*,
when there's no charter, it's invalid, its tip diverged from `ownerUid`, or its
height is below `minHeight`. **That null is fail-open by design** (a malformed
charter must not brick a group), which is why the manifest boundary above does
not rely on it.

The charter-minting `GroupService` methods take `signingKeyDomain` (from the
app's `IdentityConfig`) — never hardcoded.

## Canonical JSON

Charter payloads are signed and hashed over `canonicalJsonBytes` from
`identity`: recursively key-sorted, whitespace-free JSON. For Dart and a JS
verifier to produce identical bytes, payloads must contain **only** ASCII string
values and integers within `[0, 2^53-1]` — no floats, no nulls, no non-ASCII.
`validateCharter` enforces exactly that on untrusted input before hashing, so a
non-conforming payload is rejected rather than signed over divergently.

## Golden vector (parity lock)

Charter `[{genesis…}]` with owner uid `90ad2339401503c0a5645621a9bd89cb` and
groupId `4bbfb814115b252bfcf5f65122d92bf8cf500f4e06b28c71a6276b2b341b0f29`
validates in `test/ownership_charter_test.dart` and in the server-side
verifier's test suite. If either side rejects it, canonical-JSON bytes, SHA-256,
or Ed25519 verification has drifted between the two implementations.

## Threat model

See the README's *Why this exists* section for the full statement — what this
defends against (the server, non-members, removed members going forward,
usurpation, rollback), what it deliberately trusts (the owner, who is inside the
trust boundary by definition), what it does not provide (per-message forward
secrecy, post-compromise security, roster-consistency proofs), and why MLS was
not used.

Two invariants that live in *calling* code, not here:

- **Rotation only helps if manifests are re-published.** `removeMember` mints a
  fresh key, but members learn it from a manifest — an app that rotates without
  re-publishing leaves everyone on the old key.
- **Manifest freshness is opt-in.** The manifest now carries a monotonic
  `publishCounter` (inside the encrypted, owner-authenticated box — a server
  can't forge or strip it without breaking the box; omitted at zero so
  unbumped fleets stay byte-identical). Publishers bump once per publish
  event via `GroupService.bumpedForPublish` and adopt the result; consumers
  persist their highest accepted counter per group and pass it to
  `decryptManifest` as `minPublishCounter` (the `minCharterHeight` pattern).
  The replayed pre-rotation manifest is then refused instead of putting
  members back on a key a removed member holds. Residuals, stated plainly:
  an UNADOPTED fleet keeps the old exposure (nothing protects until the
  publisher bumps and readers pass a floor), and the counter arbitrates
  **rollback, not divergence** — two devices bumping independently from the
  same base produce equal counters with different contents, where
  last-write-wins remains the (pre-existing) semantics.

## Out of scope (deliberately app-local)

No realtime/transport/streams, no domain payload types, no app-specific
membership semantics. Those live in the app.
