import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:fido2_plugin/fido2_plugin.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/data/fido2/ceremony.dart';
import 'package:mobile/data/fido2/protocol.dart';

class _FakeKey extends Fido2PluginPlatform {
  final calls = <Map<String, Object?>>[];
  Object? error;
  Completer<void>? gate;
  String signedRpId = 'xguard.example.com';
  int flags = 0x05;
  List<int>? credentialId;
  bool cancelled = false;

  @override
  Future<Fido2NfcStatus> nfcStatus() async => Fido2NfcStatus.enabled;

  @override
  Future<void> openNfcSettings() async {}

  @override
  Future<Fido2Assertion> getAssertion({
    required String rpId,
    required Uint8List clientDataHash,
    required List<Uint8List> allowCredentials,
    String? pin,
    required Duration timeout,
  }) async {
    calls.add({
      'rpId': rpId,
      'clientDataHash': clientDataHash,
      'allowCredentials': allowCredentials,
      'pin': pin,
      'timeout': timeout,
    });
    await gate?.future;
    if (cancelled) throw const Fido2Exception(Fido2ErrorCode.cancelled);
    final failure = error;
    if (failure != null) throw failure;
    return Fido2Assertion(
      authenticatorData: Uint8List.fromList([
        ...sha256.convert(utf8.encode(signedRpId)).bytes,
        flags,
        0,
        0,
        0,
        1,
      ]),
      signature: Uint8List.fromList([48, 1, 2]),
      credentialId: Uint8List.fromList(credentialId ?? allowCredentials.first),
    );
  }

  @override
  Future<void> cancel() async {
    cancelled = true;
    gate?.complete();
  }
}

void main() {
  late _FakeKey key;
  late Fido2CeremonyRunner runner;

  setUp(() {
    Fido2CeremonyRunner.resetForTesting();
    key = _FakeKey();
    Fido2PluginPlatform.instance = key;
    runner = Fido2CeremonyRunner(platformSupported: () => true);
  });

  Future<Fido2Outcome> run({
    String? pin = '1234',
    List<String> ids = const ['AQID'],
    String instanceUrl = 'https://xguard.example.com/',
  }) => runner.run(
    instanceUrl: instanceUrl,
    challenge: 'q83vEjRWeJA-_q83vEjRWeJA',
    credentialIds: ids,
    pin: pin,
  );

  test('asks the key for the instance RP with the canonical hash', () async {
    final outcome = await run();
    expect(outcome, isA<Fido2Signed>());
    final call = key.calls.single;
    expect(call['rpId'], 'xguard.example.com');
    expect(
      call['clientDataHash'],
      clientDataHash(
        ClientDataType.get,
        'q83vEjRWeJA-_q83vEjRWeJA',
        'https://xguard.example.com',
      ),
    );
    expect(call['allowCredentials'], [
      [1, 2, 3],
    ]);
    expect(call['pin'], '1234');
    expect(call['timeout'], fido2CeremonyTimeout);

    final credential = (outcome as Fido2Signed).credential;
    expect(
      credential.rpIdHash,
      sha256.convert(utf8.encode('xguard.example.com')).bytes,
    );
    expect(credential.credentialId, [1, 2, 3]);
    expect(credential.signature, [48, 1, 2]);
  });

  test('refuses before the key on missing PIN, bad input, or platform', () async {
    expect((await run(pin: null) as Fido2Problem).kind, Fido2ProblemKind.pinMissing);
    expect((await run(pin: '12') as Fido2Problem).kind, Fido2ProblemKind.pinTooShort);
    expect(
      (await run(ids: const []) as Fido2Problem).kind,
      Fido2ProblemKind.noKeyRegistered,
    );
    expect(
      (await run(instanceUrl: 'https://10.1.1.1') as Fido2Problem).kind,
      Fido2ProblemKind.badChallenge,
    );
    final unsupported = Fido2CeremonyRunner(platformSupported: () => false);
    final outcome = await unsupported.run(
      instanceUrl: 'https://xguard.example.com',
      challenge: 'q83vEjRWeJA-_q83vEjRWeJA',
      credentialIds: const ['AQID'],
      pin: '1234',
    );
    expect((outcome as Fido2Problem).kind, Fido2ProblemKind.unsupportedPlatform);
    expect(key.calls, isEmpty);
  });

  test('maps key errors to clear problems', () async {
    final cases = {
      const Fido2Exception(Fido2ErrorCode.pinInvalid, pinRetries: 2):
          Fido2ProblemKind.pinInvalid,
      const Fido2Exception(Fido2ErrorCode.pinBlocked):
          Fido2ProblemKind.pinBlocked,
      const Fido2Exception(Fido2ErrorCode.noCredentials):
          Fido2ProblemKind.wrongKey,
      const Fido2Exception(Fido2ErrorCode.nfcDisabled):
          Fido2ProblemKind.nfcDisabled,
      const Fido2Exception(Fido2ErrorCode.tagLost): Fido2ProblemKind.tagLost,
      const Fido2Exception(Fido2ErrorCode.pinNotSet):
          Fido2ProblemKind.pinNotSet,
      StateError('boom'): Fido2ProblemKind.unknown,
    };
    for (final MapEntry(key: error, value: kind) in cases.entries) {
      key.error = error;
      final outcome = await run() as Fido2Problem;
      expect(outcome.kind, kind, reason: '$error');
      expect(outcome.message, isNotEmpty);
    }
    key.error = const Fido2Exception(Fido2ErrorCode.pinInvalid, pinRetries: 2);
    final wrongPin = await run() as Fido2Problem;
    expect(wrongPin.message, contains('2 attempts left'));
    expect(wrongPin.retryable, isTrue);
    key.error = const Fido2Exception(Fido2ErrorCode.pinBlocked);
    expect((await run() as Fido2Problem).retryable, isFalse);
  });

  test('refuses an answer signed for another site or without UV', () async {
    key.signedRpId = 'evil.example.com';
    expect((await run() as Fido2Problem).kind, Fido2ProblemKind.badAssertion);
    key.signedRpId = 'xguard.example.com';
    key.flags = 0x01;
    expect((await run() as Fido2Problem).kind, Fido2ProblemKind.badAssertion);
    key.flags = 0x05;
    key.credentialId = [9, 9];
    expect((await run() as Fido2Problem).kind, Fido2ProblemKind.badAssertion);
  });

  test('one ceremony at a time, and a cancel ends the waiting one', () async {
    key.gate = Completer<void>();
    final first = run();
    await Future<void>.delayed(Duration.zero);
    expect((await run() as Fido2Problem).kind, Fido2ProblemKind.busy);
    await runner.cancel();
    expect((await first as Fido2Problem).kind, Fido2ProblemKind.cancelled);
    key
      ..gate = null
      ..cancelled = false;
    expect(await run(), isA<Fido2Signed>());
  });
}
