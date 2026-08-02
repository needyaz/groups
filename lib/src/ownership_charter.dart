import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as std_crypto;
import 'package:identity/identity.dart';

/// Ownership charter — a signed delegation chain proving who owns a group,
/// carried in the group manifest so it rehydrates correctly into a blank DB.
/// This file defines the format, the chain builders (genesis + transfer links),
/// and the pure validator used by both client-side enforcement and (ported to
/// another language) a server-side `claim-group` verifier.
///
/// Charter wire shape (rides JSON in the manifest):
/// ```text
/// [ { "payload": {...}, "sig": "<base64 Ed25519>" }, ... ]
/// ```
/// Every entry's payload carries the owner it establishes:
///   genesis: {v, type:"genesis", groupId, ownerUid, ownerEdPubKey,
///             ownerBoxPubKey, createdAt, nonce, idBinding}
///   link:    {v, type:"link",    groupId, ownerUid, ownerEdPubKey,
///             ownerBoxPubKey, prevHash, ts}
/// genesis.sig is by the owner's own key; each link.sig is by the PREVIOUS
/// owner's key (the outgoing owner authorizes the next).
///
/// **Every group is self-certifying**: `groupId` IS the hash of its genesis
/// payload, so no one can mint a competing genesis for an existing group.
/// `idBinding` must be `"hash"` — the historical `"legacy"` binding (which
/// skipped that check and therefore let anyone sign a genesis naming any
/// group) is no longer accepted or constructible.

const int kCharterVersion = 1;

/// Hard cap on chain length. Each entry costs an Ed25519 verify plus two
/// SHA-256-over-canonical-JSON passes, and charters ride inside manifests that
/// get persisted, re-published, and re-validated server-side — an unbounded
/// chain is a CPU DoS. Real chains are a handful of entries.
const int kMaxCharterEntries = 256;

/// Largest integer that survives a round trip through a JS `number`
/// (`Number.MAX_SAFE_INTEGER`). Timestamps above this canonicalize differently
/// in Dart and JS, which would split the two verifiers.
const int _kMaxSafeInt = 9007199254740991;

/// Exact key sets. Any missing or extra key is a rejection: an unknown field
/// would be covered by the signature but ignored by validation, and could be
/// interpreted by a future or foreign implementation.
const Set<String> _kGenesisKeys = {
  'v', 'type', 'groupId', 'ownerUid', 'ownerEdPubKey', 'ownerBoxPubKey',
  'createdAt', 'nonce', 'idBinding',
};
const Set<String> _kLinkKeys = {
  'v', 'type', 'groupId', 'ownerUid', 'ownerEdPubKey', 'ownerBoxPubKey',
  'prevHash', 'ts',
};

/// The owner an entry establishes / the validated tip owner.
class CharterOwner {
  final String uid;
  final String edPubKeyB64;
  final String boxPubKeyB64;
  const CharterOwner({
    required this.uid,
    required this.edPubKeyB64,
    required this.boxPubKeyB64,
  });
}

/// Result of [validateCharter]: [valid] with the tip [owner] and the validated
/// chain [height] (genesis = 1, each accepted transfer link +1), or invalid with
/// a machine-stable [reason]. [height] is a MONOTONIC ownership epoch: it only
/// grows as ownership is transferred, so a persisted high-water mark lets a
/// client refuse an older (shorter) but still validly-signed chain a malicious
/// server might replay to roll ownership back. Self-links (a "transfer" to the
/// current owner) are rejected precisely so height cannot be inflated by a
/// past owner pre-signing a long fork.
class CharterValidationResult {
  final bool valid;
  final String? reason;
  final CharterOwner? owner;
  final int height;
  const CharterValidationResult._(this.valid, this.reason, this.owner,
      [this.height = 0]);
  factory CharterValidationResult.invalid(String reason) =>
      CharterValidationResult._(false, reason, null);
  factory CharterValidationResult.ok(CharterOwner owner, int height) =>
      CharterValidationResult._(true, null, owner, height);
}

String _sha256Hex(Uint8List bytes) => std_crypto.sha256.convert(bytes).toString();

/// uid = first 16 bytes of SHA-256(boxPublicKey), lowercase hex — identical to
/// the identity uid derivation, so an entry's ownerUid is bound to its box key.
String _uidForBoxKey(Uint8List boxPub) {
  final digest = std_crypto.sha256.convert(boxPub).bytes;
  return digest
      .sublist(0, 16)
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();
}

/// True when every code unit is printable ASCII. Charter payloads carry only
/// base64/hex/uid strings, and [canonicalJsonBytes] only guarantees Dart/JS
/// byte-agreement for ASCII — so anything else is rejected before hashing.
bool _isAscii(String s) {
  for (final u in s.codeUnits) {
    if (u < 0x20 || u > 0x7e) return false;
  }
  return true;
}

/// Deterministic, self-certifying group id derived from a genesis payload's
/// binding fields (NOT including groupId itself — avoids circularity). Because
/// it commits to the creator's keys, an attacker cannot craft a different
/// genesis that hashes to an existing group's id (second-preimage resistance).
String charterGroupId(Map<String, Object?> genesisPayload) => _sha256Hex(
      canonicalJsonBytes({
        'v': genesisPayload['v'],
        'ownerEdPubKey': genesisPayload['ownerEdPubKey'],
        'ownerBoxPubKey': genesisPayload['ownerBoxPubKey'],
        'createdAt': genesisPayload['createdAt'],
        'nonce': genesisPayload['nonce'],
      }),
    );

/// Hash of a full entry ({payload, sig}); each link commits to the prior entry
/// via this, making the chain order tamper-evident.
String charterEntryHash(Map<String, Object?> entry) =>
    _sha256Hex(canonicalJsonBytes(entry));

/// The groupId an entry's payload declares, or null if [entry] is malformed.
/// Takes untrusted input, so it never throws.
String? charterEntryGroupId(Map<String, Object?> entry) {
  final payload = entry['payload'];
  if (payload is! Map) return null;
  final gid = payload['groupId'];
  return gid is String ? gid : null;
}

/// The timestamp an entry declares (`createdAt` on a genesis, `ts` on a link),
/// or null if malformed. [validateCharter] requires these to strictly increase
/// along the chain, so a builder appending a link must pick a `ts` greater than
/// this — see [nextCharterTimestamp].
int? charterEntryTimestamp(Map<String, Object?> entry) {
  final payload = entry['payload'];
  if (payload is! Map) return null;
  final v = payload['ts'] ?? payload['createdAt'];
  return v is int ? v : null;
}

/// A timestamp safe to put on a link appended after [prevEntry]: wall-clock
/// now, bumped past the previous entry when necessary. Two transfers inside the
/// same millisecond are legitimate and must not produce an unvalidatable chain.
int nextCharterTimestamp(Map<String, Object?> prevEntry, int now) {
  final prev = charterEntryTimestamp(prevEntry);
  if (prev == null) return now;
  return now > prev ? now : prev + 1;
}

/// Build and sign a hash-bound genesis entry: the returned payload's `groupId`
/// is the hash of the payload itself, so the group is self-certifying.
Map<String, Object?> buildCharterGenesis(
  Sodium sodium, {
  required SecureKey ownerSignSecretKey,
  required String ownerUid,
  required String ownerEdPubKeyB64,
  required String ownerBoxPubKeyB64,
  required int createdAt,
  required String nonce,
}) {
  final payload = <String, Object?>{
    'v': kCharterVersion,
    'type': 'genesis',
    'ownerUid': ownerUid,
    'ownerEdPubKey': ownerEdPubKeyB64,
    'ownerBoxPubKey': ownerBoxPubKeyB64,
    'createdAt': createdAt,
    'nonce': nonce,
    'idBinding': 'hash',
  };
  payload['groupId'] = charterGroupId(payload);
  final sig =
      signDetached(sodium, canonicalJsonBytes(payload), ownerSignSecretKey);
  return {'payload': payload, 'sig': base64.encode(sig)};
}

/// Build and sign a transfer link naming a new owner. Signed by the CURRENT
/// (outgoing) owner's key. [ts] must be strictly greater than the previous
/// entry's timestamp, and [newOwnerUid] must differ from the current owner —
/// [validateCharter] rejects both otherwise.
Map<String, Object?> buildCharterLink(
  Sodium sodium, {
  required Map<String, Object?> prevEntry,
  required SecureKey currentOwnerSignSecretKey,
  required String groupId,
  required String newOwnerUid,
  required String newOwnerEdPubKeyB64,
  required String newOwnerBoxPubKeyB64,
  required int ts,
}) {
  final payload = <String, Object?>{
    'v': kCharterVersion,
    'type': 'link',
    'groupId': groupId,
    'ownerUid': newOwnerUid,
    'ownerEdPubKey': newOwnerEdPubKeyB64,
    'ownerBoxPubKey': newOwnerBoxPubKeyB64,
    'prevHash': charterEntryHash(prevEntry),
    'ts': ts,
  };
  final sig = signDetached(
      sodium, canonicalJsonBytes(payload), currentOwnerSignSecretKey);
  return {'payload': payload, 'sig': base64.encode(sig)};
}

/// Validate a charter chain for [expectedGroupId] and return the tip owner.
/// Pure and deterministic — no I/O. A server-side verifier mirrors this
/// exactly. Every failure returns a stable [reason] rather than throwing.
///
/// Input is hostile by construction (charters arrive inside peer-authored
/// manifests), so every payload is schema-checked — exact key set, integer
/// types within JS-safe bounds, ASCII strings — BEFORE it is hashed or
/// verified. That check is load-bearing for cross-language parity, not just
/// hygiene: `{"v":1.0}` compares equal to `1` in Dart but canonicalizes to
/// `1.0` here and `1` in JS, which would let a chain verify in one language
/// and not the other.
CharterValidationResult validateCharter(
  Sodium sodium,
  List<Object?> chain,
  String expectedGroupId,
) {
  if (chain.isEmpty) return CharterValidationResult.invalid('empty_chain');
  if (chain.length > kMaxCharterEntries) {
    return CharterValidationResult.invalid('chain_too_long');
  }

  String? prevOwnerEdB64; // key that must sign the next link
  String? prevOwnerUid; // to reject self-links
  int prevTs = -1; // to require strictly increasing timestamps
  Map<String, Object?>? prevEntry;
  CharterOwner? owner;

  for (var i = 0; i < chain.length; i++) {
    final entry = chain[i];
    if (entry is! Map) {
      return CharterValidationResult.invalid('entry_${i}_not_map');
    }
    // Exactly {payload, sig} — nothing else is covered by the signature.
    if (entry.length != 2 ||
        !entry.containsKey('payload') ||
        !entry.containsKey('sig')) {
      return CharterValidationResult.invalid('entry_${i}_malformed');
    }
    final rawPayload = entry['payload'];
    final sig = entry['sig'];
    if (rawPayload is! Map || sig is! String) {
      return CharterValidationResult.invalid('entry_${i}_malformed');
    }
    final p = rawPayload.cast<String, Object?>();

    final isGenesis = i == 0;
    final expectedType = isGenesis ? 'genesis' : 'link';
    if (p['type'] != expectedType) {
      return CharterValidationResult.invalid(
          isGenesis ? 'first_entry_not_genesis' : 'entry_${i}_not_link');
    }
    // Exact key set: no missing fields, no extras riding under the signature.
    final allowed = isGenesis ? _kGenesisKeys : _kLinkKeys;
    if (p.length != allowed.length || !allowed.every(p.containsKey)) {
      return CharterValidationResult.invalid('entry_${i}_bad_schema');
    }
    // Strict types. `is int` rejects the float/bigint forms that canonicalize
    // differently in Dart and JS.
    if (p['v'] is! int || p['v'] != kCharterVersion) {
      return CharterValidationResult.invalid('entry_${i}_bad_version');
    }
    final tsField = isGenesis ? 'createdAt' : 'ts';
    final tsValue = p[tsField];
    if (tsValue is! int || tsValue < 0 || tsValue > _kMaxSafeInt) {
      return CharterValidationResult.invalid('entry_${i}_bad_timestamp');
    }
    for (final key in allowed) {
      if (key == 'v' || key == tsField) continue;
      final v = p[key];
      if (v is! String || !_isAscii(v)) {
        return CharterValidationResult.invalid('entry_${i}_bad_field_$key');
      }
    }

    if (p['groupId'] != expectedGroupId) {
      return CharterValidationResult.invalid('entry_${i}_groupid_mismatch');
    }
    final ownerUid = p['ownerUid']! as String;
    final edB64 = p['ownerEdPubKey']! as String;
    final boxB64 = p['ownerBoxPubKey']! as String;
    final Uint8List edPub, boxPub, sigBytes;
    try {
      edPub = base64.decode(edB64);
      boxPub = base64.decode(boxB64);
      sigBytes = base64.decode(sig);
    } catch (_) {
      return CharterValidationResult.invalid('entry_${i}_bad_base64');
    }
    if (_uidForBoxKey(boxPub) != ownerUid) {
      return CharterValidationResult.invalid(
          'entry_${i}_uid_not_bound_to_box_key');
    }

    final payloadBytes = canonicalJsonBytes(p);

    if (isGenesis) {
      // Only hash-binding is accepted: the groupId must BE the hash of this
      // payload. The old "legacy" binding skipped this and let anyone sign a
      // genesis naming any group.
      if (p['idBinding'] != 'hash') {
        return CharterValidationResult.invalid('genesis_not_hash_bound');
      }
      if (charterGroupId(p) != expectedGroupId) {
        return CharterValidationResult.invalid('genesis_hash_binding_mismatch');
      }
      if (!verifyDetached(sodium, payloadBytes, sigBytes, edPub)) {
        return CharterValidationResult.invalid('genesis_signature_invalid');
      }
    } else {
      if (p['prevHash'] != charterEntryHash(prevEntry!)) {
        return CharterValidationResult.invalid('entry_${i}_prevhash_mismatch');
      }
      // A "transfer" to the sitting owner is not a transfer. Allowing it would
      // let a past owner pre-sign an arbitrarily long fork of self-links and
      // win any longest-chain/high-water comparison against the legitimate one.
      if (ownerUid == prevOwnerUid) {
        return CharterValidationResult.invalid('entry_${i}_self_link');
      }
      if (tsValue <= prevTs) {
        return CharterValidationResult.invalid('entry_${i}_ts_not_increasing');
      }
      final Uint8List prevEd;
      try {
        prevEd = base64.decode(prevOwnerEdB64!);
      } catch (_) {
        return CharterValidationResult.invalid('entry_${i}_bad_prev_key');
      }
      // The OUTGOING owner must have signed this transfer.
      if (!verifyDetached(sodium, payloadBytes, sigBytes, prevEd)) {
        return CharterValidationResult.invalid(
            'entry_${i}_signature_not_by_prior_owner');
      }
    }

    owner =
        CharterOwner(uid: ownerUid, edPubKeyB64: edB64, boxPubKeyB64: boxB64);
    prevOwnerEdB64 = edB64;
    prevOwnerUid = ownerUid;
    prevTs = tsValue;
    prevEntry = entry.cast<String, Object?>();
  }

  return CharterValidationResult.ok(owner!, chain.length);
}

/// The owner box public key that incoming owner-authored manifests MUST be
/// authenticated against, per the charter — or `null` when charter enforcement
/// does **not** apply. Returns null (fail open, no enforcement) when:
///   - there is no charter (group predates charters / not yet chartered);
///   - the charter is invalid (don't brick a group on a malformed charter);
///   - the charter tip has diverged from [ownerUid] (e.g. an ownership transfer
///     the deferred transfer-link hasn't recorded — we can't verify it, so we
///     stop enforcing rather than reject a legitimate new owner);
///   - the validated height is below [minHeight] (a replayed older chain).
///
/// When non-null, a manifest that does not authenticate against this key is a
/// usurpation attempt and must be rejected.
///
/// Pass [minHeight] — a persisted high-water mark of the greatest height ever
/// seen for this group — to get anti-rollback enforcement. Omitting it accepts
/// any validly-signed chain, including a shorter historical one.
Uint8List? charterEnforcedOwnerKey(
  Sodium sodium,
  List<Object?>? charter,
  String ownerUid,
  String groupId, {
  int minHeight = 0,
}) =>
    charterEnforcedOwner(sodium, charter, ownerUid, groupId,
            minHeight: minHeight)
        ?.key;

/// Like [charterEnforcedOwnerKey] but also returns the validated chain [height]
/// (the monotonic ownership epoch — see [CharterValidationResult.height]), so a
/// caller can persist it as the new high-water mark. Null under exactly the
/// same fail-open conditions.
({Uint8List key, int height})? charterEnforcedOwner(
  Sodium sodium,
  List<Object?>? charter,
  String ownerUid,
  String groupId, {
  int minHeight = 0,
}) {
  if (charter == null) return null;
  final result = validateCharter(sodium, charter, groupId);
  if (!result.valid || result.owner == null) return null;
  if (result.owner!.uid != ownerUid) return null;
  if (result.height < minHeight) return null;
  try {
    return (key: base64.decode(result.owner!.boxPubKeyB64), height: result.height);
  } catch (_) {
    return null;
  }
}
