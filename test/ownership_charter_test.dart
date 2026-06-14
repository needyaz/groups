/// Ownership charter validation + the Dart↔Deno golden-vector parity anchor.
/// Validating the shared vector proves canonical bytes + SHA-256 + Ed25519
/// verification are byte-identical to the source (and the Deno verifier).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:groups/groups.dart';

const _vectorUid = '90ad2339401503c0a5645621a9bd89cb';
const _vectorGroupId =
    '4bbfb814115b252bfcf5f65122d92bf8cf500f4e06b28c71a6276b2b341b0f29';
const _vectorJson =
    '[{"payload":{"v":1,"type":"genesis","ownerUid":"90ad2339401503c0a5645621a9bd89cb","ownerEdPubKey":"aygleX84GS9sOXBg5Z5+/s977qBt3NXSYrQibaoGXss=","ownerBoxPubKey":"W/Vcc7guviK+gPNDBmevVw+uJVamQV5rMNQGUwCqlH0=","createdAt":1717000000000,"nonce":"Zml4ZWQtbm9uY2UtMDAx","idBinding":"hash","groupId":"4bbfb814115b252bfcf5f65122d92bf8cf500f4e06b28c71a6276b2b341b0f29"},"sig":"r804JOipmL719llDfMPAMOIPihPlfXsGxq9ULUw7h5x8z1BijJ4i7b/sHsYi60/NvyDYs0FULwz3cVCETKAbBA=="}]';

void main() {
  late Sodium sodium;

  setUpAll(() async {
    sodium = await SodiumInit.init();
  });

  test('validates the shared golden vector (parity anchor with Deno)', () {
    final chain = jsonDecode(_vectorJson) as List<Object?>;
    final r = validateCharter(sodium, chain, _vectorGroupId);
    expect(r.valid, isTrue, reason: r.reason);
    expect(r.owner!.uid, _vectorUid);
  });

  test('charterEntryGroupId of the genesis matches the vector groupId', () {
    final chain = jsonDecode(_vectorJson) as List<Object?>;
    final genesis = (chain.first! as Map).cast<String, Object?>();
    expect(charterEntryGroupId(genesis), _vectorGroupId);
  });

  test('empty chain is invalid', () {
    final r = validateCharter(sodium, const [], 'gid');
    expect(r.valid, isFalse);
    expect(r.reason, 'empty_chain');
  });

  test('a tampered genesis payload is rejected', () {
    final chain = jsonDecode(_vectorJson) as List<Object?>;
    final entry = (chain.first! as Map).cast<String, Object?>();
    final payload = (entry['payload']! as Map).cast<String, Object?>();
    payload['ownerUid'] = 'deadbeefdeadbeefdeadbeefdeadbeef';
    final r = validateCharter(sodium, chain, _vectorGroupId);
    expect(r.valid, isFalse);
  });

  test('a freshly built genesis validates and is hash-bound', () {
    final id = generateIdentity(sodium);
    final signing =
        deriveSigningKeyPair(sodium, id.seed, domain: 'vault-group-signing');
    final genesis = buildCharterGenesis(
      sodium,
      ownerSignSecretKey: signing.secretKey,
      ownerUid: id.uid,
      ownerEdPubKeyB64: base64.encode(signing.publicKey),
      ownerBoxPubKeyB64: base64.encode(id.keyPair.publicKey),
      createdAt: 1717000000000,
      nonce: base64.encode(Uint8List.fromList(List<int>.generate(16, (i) => i))),
    );
    signing.secretKey.dispose();

    final gid = charterEntryGroupId(genesis);
    final r = validateCharter(sodium, [genesis], gid);
    expect(r.valid, isTrue, reason: r.reason);
    expect(r.owner!.uid, id.uid);
  });
}
