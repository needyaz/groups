import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as std_crypto;
import 'package:identity/identity.dart';

/// Ownership charter — a signed delegation chain proving who owns a group,
/// carried in the group manifest so it rehydrates correctly into a blank DB.
/// This file defines the format, the chain builders (genesis + transfer links),
/// and the pure validator used by both client-side enforcement and (ported to
/// Deno) a `claim-group` edge function.
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

const int kCharterVersion = 1;

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

/// Result of [validateCharter]: [valid] with the tip [owner], or invalid with a
/// machine-stable [reason].
class CharterValidationResult {
  final bool valid;
  final String? reason;
  final CharterOwner? owner;
  const CharterValidationResult._(this.valid, this.reason, this.owner);
  factory CharterValidationResult.invalid(String reason) =>
      CharterValidationResult._(false, reason, null);
  factory CharterValidationResult.ok(CharterOwner owner) =>
      CharterValidationResult._(true, null, owner);
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

/// The groupId an entry's payload declares.
String charterEntryGroupId(Map<String, Object?> entry) {
  final payload = (entry['payload']! as Map).cast<String, Object?>();
  final gid = payload['groupId'];
  return gid! as String;
}

/// Build and sign a genesis entry. For [hashBound] groups the groupId is derived
/// from the payload (self-certifying root); for legacy groups pass the existing
/// [legacyGroupId].
Map<String, Object?> buildCharterGenesis(
  Sodium sodium, {
  required SecureKey ownerSignSecretKey,
  required String ownerUid,
  required String ownerEdPubKeyB64,
  required String ownerBoxPubKeyB64,
  required int createdAt,
  required String nonce,
  bool hashBound = true,
  String? legacyGroupId,
}) {
  final payload = <String, Object?>{
    'v': kCharterVersion,
    'type': 'genesis',
    'ownerUid': ownerUid,
    'ownerEdPubKey': ownerEdPubKeyB64,
    'ownerBoxPubKey': ownerBoxPubKeyB64,
    'createdAt': createdAt,
    'nonce': nonce,
    'idBinding': hashBound ? 'hash' : 'legacy',
  };
  payload['groupId'] = hashBound
      ? charterGroupId(payload)
      : (legacyGroupId ?? (throw ArgumentError('legacyGroupId required')));
  final sig =
      signDetached(sodium, canonicalJsonBytes(payload), ownerSignSecretKey);
  return {'payload': payload, 'sig': base64.encode(sig)};
}

/// Build and sign a transfer link naming a new owner. Signed by the CURRENT
/// (outgoing) owner's key.
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
/// Pure and deterministic — no I/O. A Deno `claim-group` verifier mirrors this
/// exactly. Every failure returns a stable [reason] rather than throwing.
CharterValidationResult validateCharter(
  Sodium sodium,
  List<Object?> chain,
  String expectedGroupId,
) {
  if (chain.isEmpty) return CharterValidationResult.invalid('empty_chain');

  String? prevOwnerEdB64; // key that must sign the next link
  Map<String, Object?>? prevEntry;
  CharterOwner? owner;

  for (var i = 0; i < chain.length; i++) {
    final entry = chain[i];
    if (entry is! Map) {
      return CharterValidationResult.invalid('entry_${i}_not_map');
    }
    final rawPayload = entry['payload'];
    final sig = entry['sig'];
    if (rawPayload is! Map || sig is! String) {
      return CharterValidationResult.invalid('entry_${i}_malformed');
    }
    final p = rawPayload.cast<String, Object?>();

    if (p['v'] != kCharterVersion) {
      return CharterValidationResult.invalid('entry_${i}_bad_version');
    }
    if (p['groupId'] != expectedGroupId) {
      return CharterValidationResult.invalid('entry_${i}_groupid_mismatch');
    }
    final ownerUid = p['ownerUid'];
    final edB64 = p['ownerEdPubKey'];
    final boxB64 = p['ownerBoxPubKey'];
    if (ownerUid is! String || edB64 is! String || boxB64 is! String) {
      return CharterValidationResult.invalid('entry_${i}_missing_owner_fields');
    }
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

    if (i == 0) {
      if (p['type'] != 'genesis') {
        return CharterValidationResult.invalid('first_entry_not_genesis');
      }
      if (!verifyDetached(sodium, payloadBytes, sigBytes, edPub)) {
        return CharterValidationResult.invalid('genesis_signature_invalid');
      }
      final idBinding = p['idBinding'];
      if (idBinding == 'hash') {
        if (charterGroupId(p) != expectedGroupId) {
          return CharterValidationResult.invalid(
              'genesis_hash_binding_mismatch');
        }
      } else if (idBinding != 'legacy') {
        return CharterValidationResult.invalid('genesis_unknown_id_binding');
      }
    } else {
      if (p['type'] != 'link') {
        return CharterValidationResult.invalid('entry_${i}_not_link');
      }
      if (p['prevHash'] != charterEntryHash(prevEntry!)) {
        return CharterValidationResult.invalid('entry_${i}_prevhash_mismatch');
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
    prevEntry = entry.cast<String, Object?>();
  }

  return CharterValidationResult.ok(owner!);
}

/// The owner box public key that incoming owner-authored manifests MUST be
/// authenticated against, per the charter — or `null` when charter enforcement
/// does **not** apply. Returns null (fail open, no enforcement) when:
///   - there is no charter (legacy / un-backfilled group);
///   - the charter is invalid (don't brick a group on a malformed charter);
///   - the charter tip has diverged from [ownerUid] (e.g. an ownership transfer
///     the deferred transfer-link hasn't recorded — we can't verify it, so we
///     stop enforcing rather than reject a legitimate new owner).
///
/// When non-null, a manifest that does not authenticate against this key is a
/// usurpation attempt and must be rejected.
Uint8List? charterEnforcedOwnerKey(
  Sodium sodium,
  List<Object?>? charter,
  String ownerUid,
  String groupId,
) {
  if (charter == null) return null;
  final result = validateCharter(sodium, charter, groupId);
  if (!result.valid || result.owner == null) return null;
  if (result.owner!.uid != ownerUid) return null;
  try {
    return base64.decode(result.owner!.boxPubKeyB64);
  } catch (_) {
    return null;
  }
}
