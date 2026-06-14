/// Group + GroupMember serialization, manifest/local split, and helpers.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:groups/groups.dart';

void main() {
  test('GroupMember manifest JSON excludes local-only fields', () {
    const m = GroupMember(
      uid: 'u1',
      publicKeyB64: 'cHVi',
      edPubKeyB64: 'ZWQ=',
      displayName: 'Alice',
      localDisplayName: 'Al',
      avatarEmoji: '😀',
      avatarPhotoPath: '/x.png',
    );
    final manifest = m.toManifestJson();
    expect(manifest.containsKey('localDisplayName'), isFalse);
    expect(manifest.containsKey('avatarEmoji'), isFalse);
    expect(manifest.containsKey('avatarPhotoPath'), isFalse);
    expect(manifest['displayName'], 'Alice');
    expect(manifest['edPubKeyB64'], 'ZWQ=');

    final local = m.toJson();
    expect(local['localDisplayName'], 'Al');
    expect(local['avatarEmoji'], '😀');
  });

  test('GroupMember round-trips through local JSON', () {
    const m = GroupMember(
      uid: 'u1',
      publicKeyB64: 'cHVi',
      displayName: 'Alice',
      avatarPlain: true,
    );
    final rt = GroupMember.fromJson(m.toJson());
    expect(rt.uid, 'u1');
    expect(rt.displayName, 'Alice');
    expect(rt.avatarPlain, isTrue);
  });

  test('GroupMember.name prefers local, then display, then truncated uid', () {
    const local = GroupMember(
        uid: 'u', publicKeyB64: 'x', displayName: 'D', localDisplayName: 'L');
    expect(local.name, 'L');
    const display = GroupMember(uid: 'u', publicKeyB64: 'x', displayName: 'D');
    expect(display.name, 'D');
    const bare = GroupMember(uid: 'abcdef0123456789wxyz', publicKeyB64: 'x');
    expect(bare.name, 'abcdef01…wxyz');
  });

  test('resolvedAvatarPath: plain suppresses, override wins, else received', () {
    const plain = GroupMember(uid: 'u', publicKeyB64: 'x', avatarPlain: true);
    expect(plain.resolvedAvatarPath('/recv.png'), isNull);
    const override =
        GroupMember(uid: 'u', publicKeyB64: 'x', avatarPhotoPath: '/o.png');
    expect(override.resolvedAvatarPath('/recv.png'), '/o.png');
    const none = GroupMember(uid: 'u', publicKeyB64: 'x');
    expect(none.resolvedAvatarPath('/recv.png'), '/recv.png');
  });

  test('Group round-trips through local JSON incl. groupKey + charter', () {
    final g = Group(
      groupId: 'g1',
      name: 'Fam',
      ownerUid: 'u1',
      members: const [
        GroupMember(uid: 'u1', publicKeyB64: 'cHVi', localDisplayName: 'Me'),
      ],
      groupKey: Uint8List.fromList(List<int>.generate(32, (i) => i)),
      createdAt: 123,
      manifestUpdatedAt: 456,
      charter: [
        {
          'payload': {'type': 'genesis'},
          'sig': 'x',
        },
      ],
    );
    final rt = Group.fromJson(
        jsonDecode(jsonEncode(g.toJson())) as Map<String, dynamic>);
    expect(rt.groupId, 'g1');
    expect(rt.name, 'Fam');
    expect(rt.groupKey, equals(g.groupKey));
    expect(rt.manifestUpdatedAt, 456);
    expect(rt.charter, isNotNull);
    expect(rt.members.single.uid, 'u1');
    // local-only field survives local JSON round-trip
    expect(rt.members.single.localDisplayName, 'Me');
  });

  test('Group manifest JSON excludes local-only fields', () {
    final g = Group(
      groupId: 'g1',
      name: 'Fam',
      ownerUid: 'u1',
      members: const [
        GroupMember(uid: 'u1', publicKeyB64: 'cHVi', localDisplayName: 'Me'),
      ],
      groupKey: Uint8List(32),
      createdAt: 1,
      manifestUpdatedAt: 99,
    );
    final manifest = g.toManifestJson();
    expect(manifest.containsKey('manifestUpdatedAt'), isFalse);
    final firstMember = (manifest['members'] as List).first as Map;
    expect(firstMember.containsKey('localDisplayName'), isFalse);
  });
}
