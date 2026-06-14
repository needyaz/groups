import 'dart:convert';
import 'dart:typed_data';

import 'package:identity/identity.dart';

import 'group.dart';
import 'ownership_charter.dart';

/// Generic end-to-end-encrypted group membership operations: create, add/remove
/// members (with key rotation), ownership transfer (with charter), per-member
/// manifest crypto (DH), and group-key blob crypto.
///
/// App domain payloads (vault items, locations, etc.) are encrypted with
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
        groupId: charterEntryGroupId(genesis),
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

  /// Trust-on-first-upgrade backfill for groups that predate charters: if
  /// [identity] owns [group] and it has no charter, mint a **legacy** genesis
  /// (the groupId stays the existing id — not hash-bound, since it wasn't
  /// derived from a genesis). Returns the group unchanged for non-owners or
  /// already-chartered groups. Idempotent.
  static Group backfillCharter({
    required Sodium sodium,
    required Group group,
    required Identity identity,
    required String signingKeyDomain,
  }) {
    if (group.charter != null) return group;
    if (group.ownerUid != identity.uid) return group;
    final signing =
        deriveSigningKeyPair(sodium, identity.seed, domain: signingKeyDomain);
    try {
      final genesis = buildCharterGenesis(
        sodium,
        ownerSignSecretKey: signing.secretKey,
        ownerUid: identity.uid,
        ownerEdPubKeyB64: base64.encode(signing.publicKey),
        ownerBoxPubKeyB64: base64.encode(identity.keyPair.publicKey),
        createdAt: group.createdAt,
        nonce: base64.encode(sodium.randombytes.buf(16)),
        hashBound: false,
        legacyGroupId: group.groupId,
      );
      return group.copyWith(charter: [genesis]);
    } finally {
      signing.secretKey.dispose();
    }
  }

  static Group addMember(Group group, GroupMember member) {
    // Idempotent: if already present, return unchanged.
    if (group.memberByUid(member.uid) != null) return group;
    return group.copyWith(members: [...group.members, member]);
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

  /// Pure ownership-uid change (no charter). Used for the uid mechanics and by
  /// [transferOwnershipWithCharter] as its fallback.
  static Group transferOwnership(Group group, String newOwnerUid) {
    assert(
      group.memberByUid(newOwnerUid) != null,
      'New owner must be a member of the group',
    );
    return group.copyWith(ownerUid: newOwnerUid);
  }

  /// Transfer ownership to [newOwnerUid], appending a signed link to the charter
  /// so the chain's tip names the new owner. The link is signed by the OUTGOING
  /// owner ([currentOwner]) and names the new owner's Ed25519 key, learned from
  /// the member's piggybacked publishes ([GroupMember.edPubKeyB64]).
  ///
  /// If there's no charter, or the new owner's ed key isn't known yet, falls
  /// back to a plain [transferOwnership]: the owner changes but the charter
  /// isn't extended.
  static Group transferOwnershipWithCharter({
    required Sodium sodium,
    required Group group,
    required Identity currentOwner,
    required String newOwnerUid,
    required String signingKeyDomain,
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
          ts: DateTime.now().millisecondsSinceEpoch,
        );
        return group
            .copyWith(ownerUid: newOwnerUid, charter: [...charter, link]);
      } finally {
        signing.secretKey.dispose();
      }
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
    final box = deriveSharedSecret(
        sodium, memberPublicKey, ownerIdentity.keyPair.secretKey);
    try {
      return encryptBlobWithBox(sodium, group.toManifestJson(), box);
    } finally {
      box.dispose();
    }
  }

  /// Decrypt a manifest blob using DH(mySecretKey, ownerPublicKey).
  static Group decryptManifest({
    required Sodium sodium,
    required String blob,
    required Identity myIdentity,
    required Uint8List ownerPublicKey,
  }) {
    final box = deriveSharedSecret(
        sodium, ownerPublicKey, myIdentity.keyPair.secretKey);
    try {
      final data = decryptBlobWithBox(sodium, blob, box) as Map<String, dynamic>;
      return Group.fromJson(data);
    } finally {
      box.dispose();
    }
  }

  /// Encrypt arbitrary JSON-serialisable [data] with the group's symmetric key.
  /// Returns base64(nonce || ciphertext). This is how an app encrypts its own
  /// domain payloads (vault items, etc.) for the group.
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
