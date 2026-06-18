/// GroupService: creation + charter, membership, key rotation, manifest DH
/// round-trip, ownership transfer, and group-key blob crypto.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:groups/groups.dart';

void main() {
  late Sodium sodium;
  const signingDomain = 'vault-group-signing';

  setUpAll(() async {
    sodium = await SodiumInit.init();
  });

  test('createGroup mints a hash-bound, self-validating charter', () {
    final id = generateIdentity(sodium);
    final g = GroupService.createGroup(
      sodium: sodium,
      name: 'Family',
      identity: id,
      displayName: 'Mom',
      signingKeyDomain: signingDomain,
    );
    expect(g.ownerUid, id.uid);
    expect(g.members.single.uid, id.uid);
    expect(g.members.single.displayName, 'Mom');
    expect(g.charter, isNotNull);
    expect(g.charter!.length, 1);
    // groupId is the SHA-256 hash of the genesis (64-hex).
    expect(RegExp(r'^[0-9a-f]{64}$').hasMatch(g.groupId), isTrue);

    final r = validateCharter(sodium, g.charter!, g.groupId);
    expect(r.valid, isTrue, reason: r.reason);
    expect(r.owner!.uid, id.uid);
  });

  test('addMember is idempotent', () {
    final id = generateIdentity(sodium);
    var g = GroupService.createGroup(
        sodium: sodium, name: 'G', identity: id, signingKeyDomain: signingDomain);
    const m = GroupMember(uid: 'other', publicKeyB64: 'cHVi');
    g = GroupService.addMember(g, m);
    g = GroupService.addMember(g, m);
    expect(g.members.where((x) => x.uid == 'other').length, 1);
  });

  test('removeMember drops the member and rotates the key', () {
    final id = generateIdentity(sodium);
    var g = GroupService.createGroup(
        sodium: sodium, name: 'G', identity: id, signingKeyDomain: signingDomain);
    final originalKey = Uint8List.fromList(g.groupKey);
    g = GroupService.addMember(
        g, const GroupMember(uid: 'other', publicKeyB64: 'cHVi'));
    g = GroupService.removeMember(
        sodium: sodium, group: g, memberUid: 'other');
    expect(g.memberByUid('other'), isNull);
    expect(g.groupKey, isNot(equals(originalKey)));
    expect(g.groupKey.length, 32);
  });

  test('manifest encrypt→decrypt round-trips between owner and member', () {
    final owner = generateIdentity(sodium);
    final member = generateIdentity(sodium);
    var g = GroupService.createGroup(
        sodium: sodium,
        name: 'Trip',
        identity: owner,
        signingKeyDomain: signingDomain);
    g = GroupService.addMember(
      g,
      GroupMember(
          uid: member.uid,
          publicKeyB64: base64.encode(member.keyPair.publicKey)),
    );

    final blob = GroupService.encryptManifestFor(
      sodium: sodium,
      group: g,
      ownerIdentity: owner,
      memberPublicKey: member.keyPair.publicKey,
    );
    final decoded = GroupService.decryptManifest(
      sodium: sodium,
      blob: blob,
      myIdentity: member,
      ownerPublicKey: owner.keyPair.publicKey,
    );
    expect(decoded.groupId, g.groupId);
    expect(decoded.name, 'Trip');
    expect(decoded.groupKey, equals(g.groupKey));
    expect(decoded.members.map((m) => m.uid),
        containsAll(<String>[owner.uid, member.uid]));
  });

  test('transferOwnershipWithCharter appends a valid link to the new owner', () {
    final owner = generateIdentity(sodium);
    final next = generateIdentity(sodium);
    // The new owner's ed key must be known (learned from piggyback in prod).
    final nextEd =
        deriveSigningKeyPair(sodium, next.seed, domain: signingDomain);
    var g = GroupService.createGroup(
        sodium: sodium, name: 'G', identity: owner, signingKeyDomain: signingDomain);
    g = GroupService.addMember(
      g,
      GroupMember(
        uid: next.uid,
        publicKeyB64: base64.encode(next.keyPair.publicKey),
        edPubKeyB64: base64.encode(nextEd.publicKey),
      ),
    );

    final g2 = GroupService.transferOwnershipWithCharter(
      sodium: sodium,
      group: g,
      currentOwner: owner,
      newOwnerUid: next.uid,
      signingKeyDomain: signingDomain,
    );
    expect(g2.ownerUid, next.uid);
    expect(g2.charter!.length, 2);

    final r = validateCharter(sodium, g2.charter!, g2.groupId);
    expect(r.valid, isTrue, reason: r.reason);
    expect(r.owner!.uid, next.uid);
    nextEd.secretKey.dispose();
  });

  test('encryptWithGroupKey→decryptWithGroupKey round-trips arbitrary data', () {
    final key = Uint8List.fromList(List<int>.generate(32, (i) => (i * 7) % 256));
    final blob = GroupService.encryptWithGroupKey(
        sodium: sodium, data: {'item': 'doc', 'n': 7}, groupKey: key);
    final back = GroupService.decryptWithGroupKey(
        sodium: sodium, blob: blob, groupKey: key) as Map<String, dynamic>;
    expect(back['item'], 'doc');
    expect(back['n'], 7);
  });

  test('setRole promotes a member to co-owner without rotating the key', () {
    final owner = generateIdentity(sodium);
    var g = GroupService.createGroup(
        sodium: sodium, name: 'G', identity: owner, signingKeyDomain: signingDomain);
    final originalKey = Uint8List.fromList(g.groupKey);
    g = GroupService.addMember(
        g, const GroupMember(uid: 'co', publicKeyB64: 'cHVi'));
    g = GroupService.setRole(g, 'co', GroupRole.coOwner);
    expect(g.memberByUid('co')!.role, GroupRole.coOwner);
    expect(g.canAccessHidden('co'), isTrue);
    // Promotion is not a key event — a co-owner already held the group key.
    expect(g.groupKey, equals(originalKey));
    // Unknown uid is a no-op: returns the group unchanged.
    expect(identical(GroupService.setRole(g, 'ghost', GroupRole.coOwner), g),
        isTrue);
  });

  test('sealKeyForMember → unsealKey round-trips only for the named member', () {
    final recipient = generateIdentity(sodium);
    final stranger = generateIdentity(sodium);
    final member = GroupMember(
        uid: recipient.uid,
        publicKeyB64: base64.encode(recipient.keyPair.publicKey));
    final rawKey =
        Uint8List.fromList(List<int>.generate(32, (i) => (i * 5 + 1) % 256));

    final sealed = GroupService.sealKeyForMember(
        sodium: sodium, member: member, keyBytes: rawKey);

    final opened = GroupService.unsealKey(
        sodium: sodium, sealed: sealed, myKeyPair: recipient.keyPair);
    expect(opened, equals(rawKey));

    // A non-recipient cannot open it.
    final denied = GroupService.unsealKey(
        sodium: sodium, sealed: sealed, myKeyPair: stranger.keyPair);
    expect(denied, isNull);
  });
}
