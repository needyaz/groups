/// GroupService: creation + charter, membership, key rotation, manifest DH
/// round-trip and its validation boundary, ownership transfer, and group-key
/// blob crypto.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:groups/groups.dart';

void main() {
  late Sodium sodium;
  const signingDomain = 'spec-group-signing';

  setUpAll(() async {
    sodium = await SodiumInit.init();
  });

  /// A roster entry whose uid is genuinely derived from its own box key.
  GroupMember memberFor(Identity id, {String? edPubKeyB64, String? name}) =>
      GroupMember(
        uid: id.uid,
        publicKeyB64: base64.encode(id.keyPair.publicKey),
        edPubKeyB64: edPubKeyB64,
        displayName: name,
      );

  String edKeyOf(Identity id) {
    final kp = deriveSigningKeyPair(sodium, id.seed, domain: signingDomain);
    final b64 = base64.encode(kp.publicKey);
    kp.secretKey.dispose();
    return b64;
  }

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
    expect(r.height, 1);
  });

  group('addMember uid↔key binding', () {
    test('is idempotent for a self-consistent member', () {
      final id = generateIdentity(sodium);
      final other = generateIdentity(sodium);
      var g = GroupService.createGroup(
          sodium: sodium,
          name: 'G',
          identity: id,
          signingKeyDomain: signingDomain);
      g = GroupService.addMember(g, memberFor(other));
      g = GroupService.addMember(g, memberFor(other));
      expect(g.members.where((x) => x.uid == other.uid).length, 1);
    });

    test('rejects a roster entry whose uid does not match its box key', () {
      // The attack: an entry naming Alice while carrying Mallory's key, so
      // anything "sealed to Alice" is readable by Mallory.
      final owner = generateIdentity(sodium);
      final mallory = generateIdentity(sodium);
      final g = GroupService.createGroup(
          sodium: sodium,
          name: 'G',
          identity: owner,
          signingKeyDomain: signingDomain);
      final spoofed = GroupMember(
        uid: 'a' * 32,
        publicKeyB64: base64.encode(mallory.keyPair.publicKey),
      );
      expect(() => GroupService.addMember(g, spoofed),
          throwsA(isA<ArgumentError>()));
      expect(GroupService.isMemberSelfConsistent(spoofed), isFalse);
    });

    test('rejects a malformed or wrong-length public key', () {
      final owner = generateIdentity(sodium);
      final g = GroupService.createGroup(
          sodium: sodium,
          name: 'G',
          identity: owner,
          signingKeyDomain: signingDomain);
      expect(
          () => GroupService.addMember(
              g, const GroupMember(uid: 'x', publicKeyB64: 'cHVi')),
          throwsA(isA<ArgumentError>()));
      expect(
          () => GroupService.addMember(
              g, const GroupMember(uid: 'x', publicKeyB64: 'not base64!!')),
          throwsA(isA<ArgumentError>()));
    });
  });

  test('removeMember drops the member and rotates the key', () {
    final id = generateIdentity(sodium);
    final other = generateIdentity(sodium);
    var g = GroupService.createGroup(
        sodium: sodium,
        name: 'G',
        identity: id,
        signingKeyDomain: signingDomain);
    final originalKey = Uint8List.fromList(g.groupKey);
    g = GroupService.addMember(g, memberFor(other));
    g = GroupService.removeMember(
        sodium: sodium, group: g, memberUid: other.uid);
    expect(g.memberByUid(other.uid), isNull);
    expect(g.groupKey, isNot(equals(originalKey)));
    expect(g.groupKey.length, 32);
  });

  test('removeMember rotates even when the uid was not a member', () {
    final id = generateIdentity(sodium);
    final g = GroupService.createGroup(
        sodium: sodium,
        name: 'G',
        identity: id,
        signingKeyDomain: signingDomain);
    final originalKey = Uint8List.fromList(g.groupKey);
    final g2 =
        GroupService.removeMember(sodium: sodium, group: g, memberUid: 'ghost');
    expect(g2.groupKey, isNot(equals(originalKey)));
    expect(g2.members.length, g.members.length);
  });

  group('manifest boundary', () {
    test('encrypt→decrypt round-trips between owner and member', () {
      final owner = generateIdentity(sodium);
      final member = generateIdentity(sodium);
      var g = GroupService.createGroup(
          sodium: sodium,
          name: 'Trip',
          identity: owner,
          signingKeyDomain: signingDomain);
      g = GroupService.addMember(g, memberFor(member));

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
        expectedGroupId: g.groupId,
      );
      expect(decoded, isNotNull);
      expect(decoded!.groupId, g.groupId);
      expect(decoded.name, 'Trip');
      expect(decoded.groupKey, equals(g.groupKey));
      expect(decoded.members.map((m) => m.uid),
          containsAll(<String>[owner.uid, member.uid]));
    });

    test('rejects a manifest for a DIFFERENT group (groupId pinning)', () {
      // A peer whose DH key we legitimately hold hands us a manifest naming
      // another group; without pinning, a caller upserting by the returned
      // groupId would clobber its view of that group.
      final owner = generateIdentity(sodium);
      final member = generateIdentity(sodium);
      var other = GroupService.createGroup(
          sodium: sodium,
          name: 'Other',
          identity: owner,
          signingKeyDomain: signingDomain);
      other = GroupService.addMember(other, memberFor(member));
      final blob = GroupService.encryptManifestFor(
        sodium: sodium,
        group: other,
        ownerIdentity: owner,
        memberPublicKey: member.keyPair.publicKey,
      );
      expect(
        GroupService.decryptManifest(
          sodium: sodium,
          blob: blob,
          myIdentity: member,
          ownerPublicKey: owner.keyPair.publicKey,
          expectedGroupId: 'b' * 64,
        ),
        isNull,
      );
    });

    test('drops an unbound roster entry instead of rejecting the manifest', () {
      // A corrupt/schema-drifted member entry must not block every other
      // member's sync — the entry is dropped (and so never trusted), the rest
      // of the manifest is accepted.
      final owner = generateIdentity(sodium);
      final member = generateIdentity(sodium);
      final mallory = generateIdentity(sodium);
      var g = GroupService.createGroup(
          sodium: sodium,
          name: 'G',
          identity: owner,
          signingKeyDomain: signingDomain);
      g = GroupService.addMember(g, memberFor(member));
      // Bypass addMember's guard the way a hostile/corrupt manifest would.
      final spoofed = GroupMember(
        uid: 'a' * 32,
        publicKeyB64: base64.encode(mallory.keyPair.publicKey),
      );
      final tainted = g.copyWith(members: [...g.members, spoofed]);

      final blob = GroupService.encryptManifestFor(
        sodium: sodium,
        group: tainted,
        ownerIdentity: owner,
        memberPublicKey: member.keyPair.publicKey,
      );
      final decoded = GroupService.decryptManifest(
        sodium: sodium,
        blob: blob,
        myIdentity: member,
        ownerPublicKey: owner.keyPair.publicKey,
        expectedGroupId: g.groupId,
      );
      expect(decoded, isNotNull);
      expect(decoded!.memberByUid('a' * 32), isNull, reason: 'dropped');
      expect(decoded.members.map((m) => m.uid),
          containsAll(<String>[owner.uid, member.uid]));
    });

    test('rejects a usurped manifest not signed by the charter owner', () {
      // Mallory is a member, so she holds the roster and the group key. She
      // republishes the manifest with herself as ownerUid, keeping the real
      // owner's charter. Enforcement must reject it.
      final owner = generateIdentity(sodium);
      final mallory = generateIdentity(sodium);
      final victim = generateIdentity(sodium);
      var g = GroupService.createGroup(
          sodium: sodium,
          name: 'G',
          identity: owner,
          signingKeyDomain: signingDomain);
      g = GroupService.addMember(g, memberFor(mallory));
      g = GroupService.addMember(g, memberFor(victim));

      final usurped = g.copyWith(ownerUid: mallory.uid);
      final blob = GroupService.encryptManifestFor(
        sodium: sodium,
        group: usurped,
        ownerIdentity: mallory,
        memberPublicKey: victim.keyPair.publicKey,
      );
      // The victim believes the sender is the owner it is talking to.
      expect(
        GroupService.decryptManifest(
          sodium: sodium,
          blob: blob,
          myIdentity: victim,
          ownerPublicKey: mallory.keyPair.publicKey,
          expectedGroupId: g.groupId,
        ),
        isNull,
      );
    });

    test('rejects a replayed older charter when minCharterHeight is set', () {
      final owner = generateIdentity(sodium);
      final next = generateIdentity(sodium);
      final member = generateIdentity(sodium);
      var g = GroupService.createGroup(
          sodium: sodium,
          name: 'G',
          identity: owner,
          signingKeyDomain: signingDomain);
      g = GroupService.addMember(
          g, memberFor(next, edPubKeyB64: edKeyOf(next)));
      g = GroupService.addMember(g, memberFor(member));
      // Height 1 (pre-transfer) manifest, replayed after we have seen height 2.
      final blob = GroupService.encryptManifestFor(
        sodium: sodium,
        group: g,
        ownerIdentity: owner,
        memberPublicKey: member.keyPair.publicKey,
      );
      expect(
        GroupService.decryptManifest(
            sodium: sodium,
            blob: blob,
            myIdentity: member,
            ownerPublicKey: owner.keyPair.publicKey,
            expectedGroupId: g.groupId,
            minCharterHeight: 2),
        isNull,
      );
      // Accepted when it meets the high-water mark.
      expect(
        GroupService.decryptManifest(
            sodium: sodium,
            blob: blob,
            myIdentity: member,
            ownerPublicKey: owner.keyPair.publicKey,
            expectedGroupId: g.groupId,
            minCharterHeight: 1),
        isNotNull,
      );
    });

    test('returns null (never throws) on tampered, truncated, or garbage blobs',
        () {
      final owner = generateIdentity(sodium);
      final member = generateIdentity(sodium);
      var g = GroupService.createGroup(
          sodium: sodium,
          name: 'G',
          identity: owner,
          signingKeyDomain: signingDomain);
      g = GroupService.addMember(g, memberFor(member));
      final blob = GroupService.encryptManifestFor(
        sodium: sodium,
        group: g,
        ownerIdentity: owner,
        memberPublicKey: member.keyPair.publicKey,
      );
      Group? attempt(String b) => GroupService.decryptManifest(
            sodium: sodium,
            blob: b,
            myIdentity: member,
            ownerPublicKey: owner.keyPair.publicKey,
            expectedGroupId: g.groupId,
          );

      final raw = base64.decode(blob);
      raw[raw.length - 1] ^= 0x01;
      expect(attempt(base64.encode(raw)), isNull, reason: 'tampered');
      expect(attempt(base64.encode(raw.sublist(0, 20))), isNull,
          reason: 'truncated');
      expect(attempt('not base64!!'), isNull, reason: 'garbage');
      expect(attempt(''), isNull, reason: 'empty');
      // Wrong recipient.
      expect(
        GroupService.decryptManifest(
          sodium: sodium,
          blob: blob,
          myIdentity: generateIdentity(sodium),
          ownerPublicKey: owner.keyPair.publicKey,
          expectedGroupId: g.groupId,
        ),
        isNull,
      );
    });
  });

  group('ownership transfer', () {
    test('appends a valid link naming the new owner', () {
      final owner = generateIdentity(sodium);
      final next = generateIdentity(sodium);
      var g = GroupService.createGroup(
          sodium: sodium,
          name: 'G',
          identity: owner,
          signingKeyDomain: signingDomain);
      g = GroupService.addMember(
          g, memberFor(next, edPubKeyB64: edKeyOf(next)));

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
      expect(r.height, 2);
    });

    test('refuses to silently downgrade when the ed key is unknown', () {
      final owner = generateIdentity(sodium);
      final next = generateIdentity(sodium);
      var g = GroupService.createGroup(
          sodium: sodium,
          name: 'G',
          identity: owner,
          signingKeyDomain: signingDomain);
      g = GroupService.addMember(g, memberFor(next)); // no edPubKeyB64 yet

      expect(
        () => GroupService.transferOwnershipWithCharter(
          sodium: sodium,
          group: g,
          currentOwner: owner,
          newOwnerUid: next.uid,
          signingKeyDomain: signingDomain,
        ),
        throwsA(isA<StateError>()),
      );
      // Explicit opt-in still allows it (and the charter stops enforcing).
      final downgraded = GroupService.transferOwnershipWithCharter(
        sodium: sodium,
        group: g,
        currentOwner: owner,
        newOwnerUid: next.uid,
        signingKeyDomain: signingDomain,
        allowUnchartedFallback: true,
      );
      expect(downgraded.ownerUid, next.uid);
      expect(
        charterEnforcedOwnerKey(sodium, downgraded.charter, downgraded.ownerUid,
            downgraded.groupId),
        isNull,
      );
    });

    test('transferOwnership throws for a non-member in release and debug', () {
      final owner = generateIdentity(sodium);
      final g = GroupService.createGroup(
          sodium: sodium,
          name: 'G',
          identity: owner,
          signingKeyDomain: signingDomain);
      expect(() => GroupService.transferOwnership(g, 'ghost'),
          throwsA(isA<ArgumentError>()));
    });

    test('a two-transfer chain validates to height 3', () {
      final a = generateIdentity(sodium);
      final b = generateIdentity(sodium);
      final c = generateIdentity(sodium);
      var g = GroupService.createGroup(
          sodium: sodium,
          name: 'G',
          identity: a,
          signingKeyDomain: signingDomain);
      g = GroupService.addMember(g, memberFor(b, edPubKeyB64: edKeyOf(b)));
      g = GroupService.addMember(g, memberFor(c, edPubKeyB64: edKeyOf(c)));
      g = GroupService.transferOwnershipWithCharter(
          sodium: sodium,
          group: g,
          currentOwner: a,
          newOwnerUid: b.uid,
          signingKeyDomain: signingDomain);
      g = GroupService.transferOwnershipWithCharter(
          sodium: sodium,
          group: g,
          currentOwner: b,
          newOwnerUid: c.uid,
          signingKeyDomain: signingDomain);
      final r = validateCharter(sodium, g.charter!, g.groupId);
      expect(r.valid, isTrue, reason: r.reason);
      expect(r.owner!.uid, c.uid);
      expect(r.height, 3);
    });
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
    final co = generateIdentity(sodium);
    var g = GroupService.createGroup(
        sodium: sodium,
        name: 'G',
        identity: owner,
        signingKeyDomain: signingDomain);
    final originalKey = Uint8List.fromList(g.groupKey);
    g = GroupService.addMember(g, memberFor(co));
    g = GroupService.setRole(g, co.uid, GroupRole.coOwner);
    expect(g.memberByUid(co.uid)!.role, GroupRole.coOwner);
    expect(g.canAccessHidden(co.uid), isTrue);
    // Promotion is not a key event — a co-owner already held the group key.
    expect(g.groupKey, equals(originalKey));
    // Unknown uid is a no-op: returns the group unchanged.
    expect(identical(GroupService.setRole(g, 'ghost', GroupRole.coOwner), g),
        isTrue);
  });

  group('sealKeyForMember / unsealKey', () {
    test('round-trips only for the named member', () {
      final recipient = generateIdentity(sodium);
      final stranger = generateIdentity(sodium);
      final member = memberFor(recipient);
      final rawKey =
          Uint8List.fromList(List<int>.generate(32, (i) => (i * 5 + 1) % 256));

      final sealed = GroupService.sealKeyForMember(
          sodium: sodium, member: member, keyBytes: rawKey);

      expect(
          GroupService.unsealKey(
              sodium: sodium, sealed: sealed, myKeyPair: recipient.keyPair),
          equals(rawKey));
      expect(
          GroupService.unsealKey(
              sodium: sodium, sealed: sealed, myKeyPair: stranger.keyPair),
          isNull);
    });

    test('returns null (never throws) on hostile sealed content', () {
      // Sealed boxes are anonymous: anyone with our public key can seal
      // arbitrary bytes to us, so the inner payload is untrusted.
      final me = generateIdentity(sodium);
      final hostile = sealString(sodium, ' not-base64!!', me.keyPair.publicKey);
      expect(
          GroupService.unsealKey(
              sodium: sodium, sealed: hostile, myKeyPair: me.keyPair),
          isNull);
      expect(
          GroupService.unsealKey(
              sodium: sodium, sealed: 'garbage!!', myKeyPair: me.keyPair),
          isNull);
    });
  });
}
