/// Ownership charter validation: the cross-language golden-vector parity
/// anchor, plus an adversarial suite covering every rejection path.
///
/// Charters arrive inside peer-authored manifests, so every test below feeds
/// the validator input an attacker could actually produce.
library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:groups/groups.dart';

const _vectorUid = '90ad2339401503c0a5645621a9bd89cb';
const _vectorGroupId =
    '4bbfb814115b252bfcf5f65122d92bf8cf500f4e06b28c71a6276b2b341b0f29';
const _vectorJson =
    '[{"payload":{"v":1,"type":"genesis","ownerUid":"90ad2339401503c0a5645621a9bd89cb","ownerEdPubKey":"aygleX84GS9sOXBg5Z5+/s977qBt3NXSYrQibaoGXss=","ownerBoxPubKey":"W/Vcc7guviK+gPNDBmevVw+uJVamQV5rMNQGUwCqlH0=","createdAt":1717000000000,"nonce":"Zml4ZWQtbm9uY2UtMDAx","idBinding":"hash","groupId":"4bbfb814115b252bfcf5f65122d92bf8cf500f4e06b28c71a6276b2b341b0f29"},"sig":"r804JOipmL719llDfMPAMOIPihPlfXsGxq9ULUw7h5x8z1BijJ4i7b/sHsYi60/NvyDYs0FULwz3cVCETKAbBA=="}]';

void main() {
  late Sodium sodium;
  const signingDomain = 'spec-group-signing';

  setUpAll(() async {
    sodium = await SodiumInit.init();
  });

  List<Object?> vectorChain() => jsonDecode(_vectorJson) as List<Object?>;

  /// Deep-copies the vector chain so a test can mutate one field in isolation.
  List<Object?> mutatedVector(void Function(Map<String, Object?> payload) edit) {
    final chain = jsonDecode(_vectorJson) as List<Object?>;
    final entry = (chain.first! as Map).cast<String, Object?>();
    edit((entry['payload']! as Map).cast<String, Object?>());
    return chain;
  }

  ({Identity id, KeyPair signing}) newOwner() {
    final id = generateIdentity(sodium);
    return (
      id: id,
      signing: deriveSigningKeyPair(sodium, id.seed, domain: signingDomain)
    );
  }

  Map<String, Object?> genesisFor(({Identity id, KeyPair signing}) o,
          {int createdAt = 1717000000000, String nonce = 'AAAAAAAAAAAAAAAA'}) =>
      buildCharterGenesis(
        sodium,
        ownerSignSecretKey: o.signing.secretKey,
        ownerUid: o.id.uid,
        ownerEdPubKeyB64: base64.encode(o.signing.publicKey),
        ownerBoxPubKeyB64: base64.encode(o.id.keyPair.publicKey),
        createdAt: createdAt,
        nonce: nonce,
      );

  group('golden vector (cross-language parity anchor)', () {
    test('validates to the expected owner and height', () {
      final r = validateCharter(sodium, vectorChain(), _vectorGroupId);
      expect(r.valid, isTrue, reason: r.reason);
      expect(r.owner!.uid, _vectorUid);
      expect(r.height, 1);
    });

    test('charterEntryGroupId of the genesis matches the vector groupId', () {
      final genesis = (vectorChain().first! as Map).cast<String, Object?>();
      expect(charterEntryGroupId(genesis), _vectorGroupId);
    });
  });

  group('structural rejection', () {
    test('empty chain', () {
      final r = validateCharter(sodium, const [], 'gid');
      expect(r.valid, isFalse);
      expect(r.reason, 'empty_chain');
    });

    test('over-long chain is refused before doing the work', () {
      final chain = List<Object?>.filled(kMaxCharterEntries + 1, <String, Object?>{});
      expect(validateCharter(sodium, chain, 'gid').reason, 'chain_too_long');
    });

    test('non-map entry', () {
      expect(validateCharter(sodium, ['nope'], 'gid').reason, 'entry_0_not_map');
    });

    test('entry missing payload/sig, or carrying extra keys', () {
      expect(validateCharter(sodium, [<String, Object?>{}], 'gid').reason,
          'entry_0_malformed');
      final chain = vectorChain();
      (chain.first! as Map)['extra'] = 1;
      expect(validateCharter(sodium, chain, _vectorGroupId).reason,
          'entry_0_malformed');
    });

    test('a link in first position is not a genesis', () {
      final o = newOwner();
      final g = genesisFor(o);
      final gid = charterEntryGroupId(g)!;
      final link = buildCharterLink(sodium,
          prevEntry: g,
          currentOwnerSignSecretKey: o.signing.secretKey,
          groupId: gid,
          newOwnerUid: 'b' * 32,
          newOwnerEdPubKeyB64: base64.encode(o.signing.publicKey),
          newOwnerBoxPubKeyB64: base64.encode(o.id.keyPair.publicKey),
          ts: 1717000000001);
      expect(validateCharter(sodium, [link], gid).reason,
          'first_entry_not_genesis');
      o.signing.secretKey.dispose();
    });

    test('a genesis in a later position is not a link', () {
      final o = newOwner();
      final g = genesisFor(o);
      final gid = charterEntryGroupId(g)!;
      expect(validateCharter(sodium, [g, g], gid).reason, 'entry_1_not_link');
      o.signing.secretKey.dispose();
    });
  });

  group('schema and type rejection (cross-language parity)', () {
    test('a float version is rejected even though 1.0 == 1 in Dart', () {
      // The heart of the parity risk: Dart canonicalizes this as "1.0" and
      // JS as "1", so a chain could verify in one language and not the other.
      expect(1.0 == 1, isTrue);
      final chain = mutatedVector((p) => p['v'] = 1.0);
      expect(validateCharter(sodium, chain, _vectorGroupId).reason,
          'entry_0_bad_version');
    });

    test('a float timestamp is rejected', () {
      final chain = mutatedVector((p) => p['createdAt'] = 1717000000000.0);
      expect(validateCharter(sodium, chain, _vectorGroupId).reason,
          'entry_0_bad_timestamp');
    });

    test('a timestamp beyond JS safe-integer range is rejected', () {
      final chain = mutatedVector((p) => p['createdAt'] = 9007199254740993);
      expect(validateCharter(sodium, chain, _vectorGroupId).reason,
          'entry_0_bad_timestamp');
      final negative = mutatedVector((p) => p['createdAt'] = -1);
      expect(validateCharter(sodium, negative, _vectorGroupId).reason,
          'entry_0_bad_timestamp');
    });

    test('a wrong version number is rejected', () {
      final chain = mutatedVector((p) => p['v'] = 2);
      expect(validateCharter(sodium, chain, _vectorGroupId).reason,
          'entry_0_bad_version');
    });

    test('a missing or extra payload field is rejected', () {
      final missing = mutatedVector((p) => p.remove('nonce'));
      expect(validateCharter(sodium, missing, _vectorGroupId).reason,
          'entry_0_bad_schema');
      final extra = mutatedVector((p) => p['surprise'] = 'x');
      expect(validateCharter(sodium, extra, _vectorGroupId).reason,
          'entry_0_bad_schema');
    });

    test('a non-string or non-ASCII field is rejected', () {
      final nonString = mutatedVector((p) => p['nonce'] = 42);
      expect(validateCharter(sodium, nonString, _vectorGroupId).reason,
          'entry_0_bad_field_nonce');
      final unicode = mutatedVector((p) => p['nonce'] = 'Zoë');
      expect(validateCharter(sodium, unicode, _vectorGroupId).reason,
          'entry_0_bad_field_nonce');
      final nulled = mutatedVector((p) => p['nonce'] = null);
      expect(validateCharter(sodium, nulled, _vectorGroupId).reason,
          'entry_0_bad_field_nonce');
    });

    test('undecodable base64 in a key field is rejected', () {
      final chain = mutatedVector((p) => p['ownerEdPubKey'] = '!!!!');
      expect(validateCharter(sodium, chain, _vectorGroupId).reason,
          'entry_0_bad_base64');
    });
  });

  group('binding and signature rejection', () {
    test('a chain for another group is rejected (graft)', () {
      expect(validateCharter(sodium, vectorChain(), 'b' * 64).reason,
          'entry_0_groupid_mismatch');
    });

    test('a uid not derived from its own box key is rejected', () {
      final chain =
          mutatedVector((p) => p['ownerUid'] = 'deadbeefdeadbeefdeadbeefdeadbeef');
      expect(validateCharter(sodium, chain, _vectorGroupId).reason,
          'entry_0_uid_not_bound_to_box_key');
    });

    test('a forged genesis signature is rejected', () {
      // Reached only because the uid/key pair stays self-consistent — the
      // earlier binding check would otherwise mask it.
      final o = newOwner();
      final imposter = newOwner();
      final g = genesisFor(o);
      final gid = charterEntryGroupId(g)!;
      // Re-sign the same payload with a key that isn't the named owner's.
      final payload = (g['payload']! as Map).cast<String, Object?>();
      final forged = <String, Object?>{
        'payload': payload,
        'sig': base64.encode(signDetached(
            sodium, canonicalJsonBytes(payload), imposter.signing.secretKey)),
      };
      expect(validateCharter(sodium, [forged], gid).reason,
          'genesis_signature_invalid');
      o.signing.secretKey.dispose();
      imposter.signing.secretKey.dispose();
    });

    test('a genesis claiming a groupId it does not hash to is rejected', () {
      final o = newOwner();
      final g = genesisFor(o);
      final payload = (g['payload']! as Map).cast<String, Object?>();
      payload['groupId'] = 'c' * 64; // claim someone else's id
      expect(validateCharter(sodium, [g], 'c' * 64).reason,
          'genesis_hash_binding_mismatch');
      o.signing.secretKey.dispose();
    });

    test('the removed "legacy" id binding can no longer be used', () {
      // Previously: idBinding:"legacy" skipped hash binding entirely, so an
      // attacker could self-sign a genesis naming ANY group and validate as
      // its owner. There is now no builder for it and the validator refuses.
      final o = newOwner();
      final victimGroupId = 'a' * 64;
      final payload = <String, Object?>{
        'v': 1,
        'type': 'genesis',
        'ownerUid': o.id.uid,
        'ownerEdPubKey': base64.encode(o.signing.publicKey),
        'ownerBoxPubKey': base64.encode(o.id.keyPair.publicKey),
        'createdAt': 1717000000000,
        'nonce': 'AAAAAAAAAAAAAAAA',
        'idBinding': 'legacy',
        'groupId': victimGroupId,
      };
      final forged = <String, Object?>{
        'payload': payload,
        'sig': base64.encode(signDetached(
            sodium, canonicalJsonBytes(payload), o.signing.secretKey)),
      };
      final r = validateCharter(sodium, [forged], victimGroupId);
      expect(r.valid, isFalse);
      expect(r.reason, 'genesis_not_hash_bound');
      // And enforcement refuses to hand back the forger's key.
      expect(
          charterEnforcedOwnerKey(sodium, [forged], o.id.uid, victimGroupId),
          isNull);
      o.signing.secretKey.dispose();
    });

    test('an unknown id binding is rejected', () {
      final chain = mutatedVector((p) => p['idBinding'] = 'something');
      expect(validateCharter(sodium, chain, _vectorGroupId).reason,
          'genesis_not_hash_bound');
    });
  });

  group('link chain rejection', () {
    late ({Identity id, KeyPair signing}) alice;
    late ({Identity id, KeyPair signing}) bob;
    late Map<String, Object?> genesis;
    late String gid;

    setUp(() {
      alice = newOwner();
      bob = newOwner();
      genesis = genesisFor(alice);
      gid = charterEntryGroupId(genesis)!;
    });

    tearDown(() {
      alice.signing.secretKey.dispose();
      bob.signing.secretKey.dispose();
    });

    Map<String, Object?> linkTo(
      ({Identity id, KeyPair signing}) to, {
      required SecureKey signedBy,
      Map<String, Object?>? prev,
      int ts = 1717000000001,
    }) =>
        buildCharterLink(sodium,
            prevEntry: prev ?? genesis,
            currentOwnerSignSecretKey: signedBy,
            groupId: gid,
            newOwnerUid: to.id.uid,
            newOwnerEdPubKeyB64: base64.encode(to.signing.publicKey),
            newOwnerBoxPubKeyB64: base64.encode(to.id.keyPair.publicKey),
            ts: ts);

    test('a well-formed transfer validates', () {
      final link = linkTo(bob, signedBy: alice.signing.secretKey);
      final r = validateCharter(sodium, [genesis, link], gid);
      expect(r.valid, isTrue, reason: r.reason);
      expect(r.owner!.uid, bob.id.uid);
      expect(r.height, 2);
    });

    test('a link signed by someone other than the outgoing owner is rejected',
        () {
      // Bob tries to award himself the group without Alice's signature.
      final forged = linkTo(bob, signedBy: bob.signing.secretKey);
      expect(validateCharter(sodium, [genesis, forged], gid).reason,
          'entry_1_signature_not_by_prior_owner');
    });

    test('a spliced prevHash is rejected', () {
      final link = linkTo(bob, signedBy: alice.signing.secretKey);
      final payload = (link['payload']! as Map).cast<String, Object?>();
      payload['prevHash'] = 'd' * 64;
      expect(validateCharter(sodium, [genesis, link], gid).reason,
          'entry_1_prevhash_mismatch');
    });

    test('a self-link is rejected (height cannot be inflated)', () {
      // Previously accepted: a past owner could pre-sign a long fork of
      // self-links and beat the legitimate chain on a longest-chain rule.
      final self = linkTo(alice, signedBy: alice.signing.secretKey);
      expect(validateCharter(sodium, [genesis, self], gid).reason,
          'entry_1_self_link');
    });

    test('a non-increasing timestamp is rejected', () {
      final stale =
          linkTo(bob, signedBy: alice.signing.secretKey, ts: 1717000000000);
      expect(validateCharter(sodium, [genesis, stale], gid).reason,
          'entry_1_ts_not_increasing');
    });

    test('a link grafted from another group is rejected', () {
      final other = newOwner();
      final otherGenesis = genesisFor(other, nonce: 'BBBBBBBBBBBBBBBB');
      final otherGid = charterEntryGroupId(otherGenesis)!;
      final foreign = buildCharterLink(sodium,
          prevEntry: otherGenesis,
          currentOwnerSignSecretKey: other.signing.secretKey,
          groupId: otherGid,
          newOwnerUid: bob.id.uid,
          newOwnerEdPubKeyB64: base64.encode(bob.signing.publicKey),
          newOwnerBoxPubKeyB64: base64.encode(bob.id.keyPair.publicKey),
          ts: 1717000000002);
      expect(validateCharter(sodium, [genesis, foreign], gid).reason,
          'entry_1_groupid_mismatch');
      other.signing.secretKey.dispose();
    });
  });

  group('charterEnforcedOwner', () {
    test('returns the tip owner key and height for a valid chain', () {
      final o = newOwner();
      final g = genesisFor(o);
      final gid = charterEntryGroupId(g)!;
      final enforced = charterEnforcedOwner(sodium, [g], o.id.uid, gid);
      expect(enforced, isNotNull);
      expect(enforced!.key, equals(o.id.keyPair.publicKey));
      expect(enforced.height, 1);
      o.signing.secretKey.dispose();
    });

    test('fails open (null) with no charter, an invalid chain, or a '
        'diverged ownerUid', () {
      final o = newOwner();
      final g = genesisFor(o);
      final gid = charterEntryGroupId(g)!;
      expect(charterEnforcedOwnerKey(sodium, null, o.id.uid, gid), isNull,
          reason: 'no charter');
      expect(charterEnforcedOwnerKey(sodium, const [], o.id.uid, gid), isNull,
          reason: 'invalid chain');
      expect(charterEnforcedOwnerKey(sodium, [g], 'someone-else', gid), isNull,
          reason: 'tip diverged from ownerUid');
      o.signing.secretKey.dispose();
    });

    test('refuses a chain shorter than the caller high-water mark', () {
      final o = newOwner();
      final g = genesisFor(o);
      final gid = charterEntryGroupId(g)!;
      expect(charterEnforcedOwnerKey(sodium, [g], o.id.uid, gid, minHeight: 2),
          isNull);
      expect(charterEnforcedOwnerKey(sodium, [g], o.id.uid, gid, minHeight: 1),
          isNotNull);
      o.signing.secretKey.dispose();
    });
  });

  test('charterEntryGroupId returns null on malformed entries (never throws)',
      () {
    expect(charterEntryGroupId(const {}), isNull);
    expect(charterEntryGroupId(const {'payload': 'nope'}), isNull);
    expect(charterEntryGroupId(const {'payload': <String, Object?>{}}), isNull);
    expect(charterEntryGroupId(const {'payload': {'groupId': 7}}), isNull);
  });
}
