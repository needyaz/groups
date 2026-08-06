import 'dart:convert';
import 'dart:typed_data';

import 'package:identity/identity.dart';

import 'group.dart';
import 'ownership_charter.dart';

/// How [GroupService.decryptManifest] treats a manifest whose charter fails
/// validation.
enum CharterPolicy {
  /// A present charter is AUTHORITATIVE: any validation failure — an invalid
  /// chain, a tip uid diverged from `ownerUid`, a tip box key that isn't the
  /// sending owner's, a chain below `minCharterHeight` — rejects the manifest.
  /// This is the default and the right posture when every group is created
  /// with a charter: a broken or missing one there signals a lying server.
  strict,

  /// Fail-open: on any charter validation failure, proceed exactly as if the
  /// manifest carried no charter — trust falls back to the caller-supplied
  /// `ownerPublicKey`. Every OTHER check (`expectedGroupId` pin, 32-byte group
  /// key, roster uid↔key vetting) stays fully strict.
  ///
  /// This deliberately re-opens the usurpation hole that [strict] closes: a
  /// manifest whose `ownerUid` was changed without extending the charter is
  /// ACCEPTED, trusting whichever key the caller already believes is the
  /// owner's. Choose it only when the fleet still contains groups whose
  /// charters legitimately cannot validate (legacy un-hash-bound charters
  /// draining out; an uncharted ownership transfer's permanently diverged
  /// tip) and a hard rejection would mean those groups never sync again.
  /// Callers should treat it as transitional and return to [strict] once
  /// those groups are gone.
  tolerant,
}

/// Generic end-to-end-encrypted group membership operations: create, add/remove
/// members (with key rotation), ownership transfer (with charter), per-member
/// manifest crypto (DH), and group-key blob crypto.
///
/// App domain payloads are encrypted with
/// [encryptWithGroupKey] / [decryptWithGroupKey] — this layer has no knowledge
/// of what rides inside the group key.
///
/// The three charter-minting methods take [signingKeyDomain] — the per-app
/// Ed25519 derivation domain (`IdentityConfig.signingKeyDomain`).
class GroupService {
  const GroupService();

  static Group createGroup({
    required Sodium sodium,
    required String name,
    required Identity identity,
    required String signingKeyDomain,
    String? displayName,
  }) {
    final groupKey = sodium.randombytes.buf(32);
    final createdAt = DateTime.now().millisecondsSinceEpoch;

    // Issue a hash-bound ownership charter: the genesis is signed by this
    // owner's seed-derived Ed25519 key, and the groupId IS the hash of that
    // genesis — a self-certifying root that no one else can forge a competing
    // genesis for. The creator's own member entry carries its ed key so a
    // future transfer-link can name it.
    final signing =
        deriveSigningKeyPair(sodium, identity.seed, domain: signingKeyDomain);
    try {
      final edPubKeyB64 = base64.encode(signing.publicKey);
      final member = GroupMember(
        uid: identity.uid,
        publicKeyB64: base64.encode(identity.keyPair.publicKey),
        edPubKeyB64: edPubKeyB64,
        displayName: displayName,
      );
      final genesis = buildCharterGenesis(
        sodium,
        ownerSignSecretKey: signing.secretKey,
        ownerUid: identity.uid,
        ownerEdPubKeyB64: edPubKeyB64,
        ownerBoxPubKeyB64: base64.encode(identity.keyPair.publicKey),
        createdAt: createdAt,
        nonce: base64.encode(sodium.randombytes.buf(16)),
      );
      return Group(
        // Non-null: buildCharterGenesis always sets a hash-bound groupId.
        groupId: charterEntryGroupId(genesis)!,
        name: name,
        ownerUid: identity.uid,
        members: [member],
        groupKey: groupKey,
        createdAt: createdAt,
        charter: [genesis],
      );
    } finally {
      signing.secretKey.dispose();
    }
  }

  /// Add [member] to the roster.
  ///
  /// Rejects a member whose `uid` is not the uid derived from its own box
  /// public key. A roster entry is a `(uid, publicKey)` pair from an untrusted
  /// source, and everything addressed "to that member" — sealed item keys,
  /// manifests — is encrypted to the KEY while the UI shows the UID. Without
  /// this check a roster entry can name Alice and carry Mallory's key.
  ///
  /// Idempotent: a uid already present returns the group unchanged.
  /// Throws [ArgumentError] when the pair is inconsistent.
  static Group addMember(Group group, GroupMember member) {
    if (!isMemberSelfConsistent(member)) {
      throw ArgumentError.value(
          member.uid, 'member.uid', 'uid does not match its box public key');
    }
    if (group.memberByUid(member.uid) != null) return group;
    return group.copyWith(members: [...group.members, member]);
  }

  /// True when [member]'s uid is the uid derived from its own box public key
  /// (`uidForBoxPublicKey`). False for a malformed key as well as a mismatch.
  static bool isMemberSelfConsistent(GroupMember member) {
    try {
      final key = member.publicKey;
      if (key.length != 32) return false;
      return uidForBoxPublicKey(key) == member.uid;
    } catch (_) {
      return false;
    }
  }

  static Group removeMember({
    required Sodium sodium,
    required Group group,
    required String memberUid,
  }) {
    final updated = group.members.where((m) => m.uid != memberUid).toList();
    // Always rotate key regardless of whether uid was found.
    final newKey = sodium.randombytes.buf(32);
    return group.copyWith(
        members: updated, groupKey: Uint8List.fromList(newKey));
  }

  /// Set [memberUid]'s [role] (e.g. promote a member to co-owner, or demote a
  /// co-owner back to member). Pure and additive — no key rotation, because a
  /// co-owner is already a full group-key holder.
  ///
  /// This does NOT change ownership: the billing owner remains [Group.ownerUid]
  /// and the charter tip. Returns the group unchanged if [memberUid] is absent.
  ///
  /// Demotion that requires forward secrecy on hidden material is a
  /// remove-then-re-add (which rotates the group key via [removeMember]), not a
  /// [setRole] call.
  static Group setRole(Group group, String memberUid, GroupRole role) {
    if (group.memberByUid(memberUid) == null) return group;
    final updated = group.members
        .map((m) => m.uid == memberUid ? m.copyWith(role: role) : m)
        .toList();
    return group.copyWith(members: updated);
  }

  /// Pure ownership-uid change with NO charter link.
  ///
  /// Leaves `ownerUid` diverged from the charter tip, which
  /// [charterEnforcedOwner] treats as "stop enforcing" — so this permanently
  /// disables usurpation protection for the group. Prefer
  /// [transferOwnershipWithCharter]; reach for this only when there is
  /// deliberately no charter to extend.
  ///
  /// Throws [ArgumentError] if [newOwnerUid] is not a member — this was
  /// previously an `assert`, which is stripped in release builds and so let
  /// production set `ownerUid` to an arbitrary string.
  static Group transferOwnership(Group group, String newOwnerUid) {
    if (group.memberByUid(newOwnerUid) == null) {
      throw ArgumentError.value(
          newOwnerUid, 'newOwnerUid', 'New owner must be a member of the group');
    }
    return group.copyWith(ownerUid: newOwnerUid);
  }

  /// Transfer ownership to [newOwnerUid], appending a signed link to the charter
  /// so the chain's tip names the new owner. The link is signed by the OUTGOING
  /// owner ([currentOwner]) and names the new owner's Ed25519 key, learned from
  /// the member's piggybacked publishes ([GroupMember.edPubKeyB64]).
  ///
  /// If there's no charter, or the new owner's Ed25519 key isn't known yet,
  /// this throws [StateError] unless [allowUnchartedFallback] is set.
  ///
  /// That default is deliberate. The fallback silently produces a group whose
  /// `ownerUid` no longer matches the charter tip, which turns usurpation
  /// enforcement OFF for every member — permanently, since the stale charter
  /// can never be reconciled. "The new owner's ed key hasn't piggybacked yet"
  /// is a routine, retryable condition, so the caller should retry rather than
  /// silently downgrade the group's security. Callers that genuinely want the
  /// downgrade must ask for it.
  static Group transferOwnershipWithCharter({
    required Sodium sodium,
    required Group group,
    required Identity currentOwner,
    required String newOwnerUid,
    required String signingKeyDomain,
    bool allowUnchartedFallback = false,
  }) {
    final newMember = group.memberByUid(newOwnerUid);
    final charter = group.charter;
    final newEd = newMember?.edPubKeyB64;

    if (charter != null &&
        charter.isNotEmpty &&
        newMember != null &&
        newEd != null) {
      final signing = deriveSigningKeyPair(sodium, currentOwner.seed,
          domain: signingKeyDomain);
      try {
        final prevEntry = (charter.last! as Map).cast<String, Object?>();
        final link = buildCharterLink(
          sodium,
          prevEntry: prevEntry,
          currentOwnerSignSecretKey: signing.secretKey,
          groupId: group.groupId,
          newOwnerUid: newOwnerUid,
          newOwnerEdPubKeyB64: newEd,
          newOwnerBoxPubKeyB64: newMember.publicKeyB64,
          // Bumped past the previous entry when two transfers land in the
          // same millisecond — the validator requires strict increase.
          ts: nextCharterTimestamp(
              prevEntry, DateTime.now().millisecondsSinceEpoch),
        );
        return group
            .copyWith(ownerUid: newOwnerUid, charter: [...charter, link]);
      } finally {
        signing.secretKey.dispose();
      }
    }

    if (!allowUnchartedFallback) {
      throw StateError(
        'Cannot extend the charter for this transfer '
        '(${charter == null || charter.isEmpty ? 'group has no charter' : newMember == null ? 'new owner is not a member' : "new owner's edPubKeyB64 is not known yet"}). '
        'Retry once the new owner\'s key is known, or pass '
        'allowUnchartedFallback: true to accept permanently disabling '
        'charter enforcement for this group.',
      );
    }
    return transferOwnership(group, newOwnerUid);
  }

  /// Encrypt the group manifest for [memberPublicKey] using
  /// DH(ownerSecretKey, memberPublicKey).
  static String encryptManifestFor({
    required Sodium sodium,
    required Group group,
    required Identity ownerIdentity,
    required Uint8List memberPublicKey,
  }) {
    return encryptBlobWithBoxDisposing(
      sodium,
      group.toManifestJson(),
      deriveSharedSecret(
          sodium, memberPublicKey, ownerIdentity.keyPair.secretKey),
    );
  }

  /// Decrypt and VALIDATE a manifest blob using DH(mySecretKey,
  /// [ownerPublicKey]). Returns null on any failure — this is the package's
  /// trust boundary, and every input to it is peer-authored.
  ///
  /// Beyond decrypting, this enforces:
  ///  - the manifest's `groupId` equals [expectedGroupId]. Without this pin, a
  ///    peer whose DH key you legitimately hold can hand you a manifest naming
  ///    a DIFFERENT group, and a caller upserting by the returned groupId
  ///    replaces its view of that other group.
  ///  - when a charter is present it is AUTHORITATIVE (under the default
  ///    [CharterPolicy.strict]): it must validate for that groupId, its tip uid
  ///    must equal the manifest's `ownerUid`, and [ownerPublicKey] must be the
  ///    tip's box key. Note this is deliberately stricter than
  ///    [charterEnforcedOwner], which fails open when the tip has diverged from
  ///    `ownerUid` — here that divergence IS the attack (a member who simply
  ///    claims ownership would otherwise switch enforcement off).
  ///    Pass [minCharterHeight] (a persisted high-water mark) to also reject a
  ///    replayed older chain. [CharterPolicy.tolerant] relaxes ONLY this
  ///    charter authority — see [CharterPolicy] for what that trades away.
  ///  - the group key is 32 bytes. Roster entries that fail the uid↔key
  ///    binding (see [isMemberSelfConsistent]) are DROPPED from the returned
  ///    group rather than rejecting the whole manifest — an unbound entry is
  ///    never trusted either way, and rejecting outright would let one corrupt
  ///    entry block every other member's sync.
  ///
  /// A null return means "do not trust this manifest"; it never throws on
  /// malformed or hostile input.
  static Group? decryptManifest({
    required Sodium sodium,
    required String blob,
    required Identity myIdentity,
    required Uint8List ownerPublicKey,
    required String expectedGroupId,
    int minCharterHeight = 0,
    CharterPolicy charterPolicy = CharterPolicy.strict,
  }) {
    PrecalculatedBox? box;
    try {
      box = deriveSharedSecret(
          sodium, ownerPublicKey, myIdentity.keyPair.secretKey);
      final decoded = decryptBlobWithBox(sodium, blob, box);
      if (decoded is! Map<String, dynamic>) return null;
      final group = Group.tryFromJson(decoded);
      if (group == null) return null;

      if (group.groupId != expectedGroupId) return null;
      if (group.groupKey.length != 32) return null;
      // Drop roster entries that fail the uid↔key binding rather than
      // rejecting the whole manifest. Dropping is both safer and more
      // available: an unbound entry is simply never trusted (nothing is ever
      // sealed to it), while rejecting outright would let one corrupt or
      // schema-drifted member entry block every remaining member's sync
      // indefinitely — the manifest is owner-authenticated, so the realistic
      // source of a bad entry is corruption, not an attacker.
      final vetted =
          group.members.where(isMemberSelfConsistent).toList(growable: false);
      final group2 = vetted.length == group.members.length
          ? group
          : group.copyWith(members: vetted);
      // A charter, if present, is authoritative under strict — anything short
      // of a full match is a rejection, never a fallback to "unenforced".
      // Under tolerant, a failure means "proceed as if charter == null": the
      // charter contributes no trust either way (the carried chain is data,
      // not proof), and the caller's ownerPublicKey is what's trusted.
      final charter = group.charter;
      if (charter != null &&
          !_charterAuthorizes(
            sodium: sodium,
            charter: charter,
            group: group,
            ownerPublicKey: ownerPublicKey,
            minCharterHeight: minCharterHeight,
          ) &&
          charterPolicy == CharterPolicy.strict) {
        return null;
      }
      return group2;
    } catch (_) {
      return null;
    } finally {
      box?.dispose();
    }
  }

  /// The full charter-authority check [decryptManifest] applies to a present
  /// charter: the chain validates for the group's id, meets the caller's
  /// height high-water mark, and its tip names exactly the manifest's
  /// `ownerUid` and the sending owner's box key.
  static bool _charterAuthorizes({
    required Sodium sodium,
    required List<Object?> charter,
    required Group group,
    required Uint8List ownerPublicKey,
    required int minCharterHeight,
  }) {
    final result = validateCharter(sodium, charter, group.groupId);
    if (!result.valid || result.owner == null) return false;
    if (result.height < minCharterHeight) return false;
    if (result.owner!.uid != group.ownerUid) return false;
    final Uint8List tipKey;
    try {
      tipKey = base64.decode(result.owner!.boxPubKeyB64);
    } catch (_) {
      return false;
    }
    return _bytesEqual(tipKey, ownerPublicKey);
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  /// Seal an opaque [keyBytes] (e.g. a per-item content key) to [member]'s box
  /// public key with an anonymous sealed-box. Only the holder of [member]'s
  /// secret key can open it (via [unsealKey]); the sender is not authenticated.
  ///
  /// This is a generic, key-agnostic substrate primitive: it knows nothing
  /// about what the bytes mean or where the ciphertext is stored. The app
  /// (e.g. a per-item key scheme) decides those.
  static String sealKeyForMember({
    required Sodium sodium,
    required GroupMember member,
    required Uint8List keyBytes,
  }) =>
      sealString(sodium, base64.encode(keyBytes), member.publicKey);

  /// Open a blob produced by [sealKeyForMember] with [myKeyPair]. Returns the
  /// raw key bytes, or null if this keypair is not the sealed recipient.
  /// Returns null on any failure. Sealed boxes are ANONYMOUS — anyone holding
  /// your public key can seal arbitrary bytes to you — so the inner content is
  /// untrusted and non-base64/non-UTF-8 payloads must not escape as exceptions.
  static Uint8List? unsealKey({
    required Sodium sodium,
    required String sealed,
    required KeyPair myKeyPair,
  }) {
    final opened = openSealedBytes(sodium, sealed, myKeyPair);
    if (opened == null) return null;
    try {
      // sealKeyForMember sealed the base64 text of the key; decode it back.
      return Uint8List.fromList(base64.decode(utf8.decode(opened)));
    } catch (_) {
      return null;
    }
  }

  /// Encrypt arbitrary JSON-serialisable [data] with the group's symmetric key.
  /// Returns base64(nonce || ciphertext). This is how an app encrypts its own
  /// domain payloads for the group.
  static String encryptWithGroupKey({
    required Sodium sodium,
    required Object data,
    required Uint8List groupKey,
  }) {
    final key = SecureKey.fromList(sodium, groupKey);
    try {
      return encryptBlob(sodium, data, key);
    } finally {
      key.dispose();
    }
  }

  /// Decrypt a blob produced by [encryptWithGroupKey]. Returns the decoded JSON
  /// value (`Map` or `List`); callers cast explicitly.
  static Object decryptWithGroupKey({
    required Sodium sodium,
    required String blob,
    required Uint8List groupKey,
  }) {
    final key = SecureKey.fromList(sodium, groupKey);
    try {
      return decryptBlob(sodium, blob, key);
    } finally {
      key.dispose();
    }
  }
}
