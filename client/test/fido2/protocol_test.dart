import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/data/fido2/protocol.dart';

/// Authenticator data for [rpId] with the given flags: RP ID hash, flags,
/// counter.
List<int> authData(String rpId, {int flags = 0x05}) => [
  ...sha256.convert(utf8.encode(rpId)).bytes,
  flags,
  0,
  0,
  0,
  7,
];

void main() {
  group('client data', () {
    test('matches the vector shared by Core and the desktop client', () {
      // The same vector is in Core's `fido2::tests::client_data_is_canonical`
      // and the desktop client's `client_data_matches_core`.
      expect(
        utf8.decode(
          clientDataJson(
            ClientDataType.get,
            'q83vEjRWeJA',
            'https://xguard.example.com',
          ),
        ),
        '{"type":"webauthn.get","challenge":"q83vEjRWeJA",'
        '"origin":"https://xguard.example.com","crossOrigin":false}',
      );
      expect(
        utf8.decode(
          clientDataJson(ClientDataType.create, 'a"b', 'https://h:8443'),
        ),
        r'{"type":"webauthn.create","challenge":"a\"b",'
        '"origin":"https://h:8443","crossOrigin":false}',
      );
    });

    test('escapes control characters like serde_json', () {
      expect(
        utf8.decode(clientDataJson(ClientDataType.get, 'a\\b\n\u0001', 'o')),
        r'{"type":"webauthn.get","challenge":"a\\b\n\u0001",'
        '"origin":"o","crossOrigin":false}',
      );
    });

    test('the key gets SHA-256 of the canonical bytes', () {
      final json = clientDataJson(
        ClientDataType.get,
        'q83vEjRWeJA',
        'https://xguard.example.com',
      );
      expect(
        clientDataHash(
          ClientDataType.get,
          'q83vEjRWeJA',
          'https://xguard.example.com',
        ),
        sha256.convert(json).bytes,
      );
    });
  });

  group('relying party', () {
    test('comes from the instance URL', () {
      expect(
        RelyingParty.forInstance('https://xguard.example.com/'),
        const RelyingParty(
          id: 'xguard.example.com',
          origin: 'https://xguard.example.com',
        ),
      );
      final withPort = RelyingParty.forInstance(
        'https://VPN.Example.com:8443/x/',
      );
      expect(withPort.id, 'vpn.example.com');
      expect(withPort.origin, 'https://vpn.example.com:8443');
      expect(
        RelyingParty.forInstance('https://xguard.example.com:443').origin,
        'https://xguard.example.com',
      );
      final local = RelyingParty.forInstance('http://localhost:8080/edge');
      expect(local.id, 'localhost');
      expect(local.origin, 'http://localhost:8080');
    });

    test('refuses IP addresses, non-local HTTP, userinfo, and non-ASCII hosts', () {
      for (final url in [
        'https://10.0.0.1/',
        'https://[::1]/',
        'https://example.123/',
        'http://xguard.example.com/',
        'https://user:pass@xguard.example.com/',
        'ftp://example.com/',
        'https://bücher.example/',
        'not a url',
      ]) {
        expect(
          () => RelyingParty.forInstance(url),
          throwsA(isA<Fido2ProtocolException>()),
          reason: url,
        );
      }
    });
  });

  group('challenge and credential IDs', () {
    test('are validated before the key is asked', () {
      validateChallenge('q83vEjRWeJA-_q83vEjRWeJA');
      for (final bad in [
        'short',
        'q83vEjRWeJA"q83vEjRWeJA',
        'q83vEjRWeJA+/q83vEjRWeJA',
        'a' * 129,
      ]) {
        expect(
          () => validateChallenge(bad),
          throwsA(isA<Fido2ProtocolException>()),
          reason: bad,
        );
      }

      expect(decodeCredentialIds(['AQID']), [
        [1, 2, 3],
      ]);
      expect(decodeCredentialIds(['AQID=']), [
        [1, 2, 3],
      ]);
      expect(
        () => decodeCredentialIds([]),
        throwsA(isA<NoCredentialsOffered>()),
      );
      expect(
        () => decodeCredentialIds(['not base64!']),
        throwsA(isA<Fido2ProtocolException>()),
      );
      expect(
        () => decodeCredentialIds([
          base64Url.encode(Uint8List(1024)).replaceAll('=', ''),
        ]),
        throwsA(isA<Fido2ProtocolException>()),
      );
      expect(
        () => decodeCredentialIds(List.filled(33, 'AQID')),
        throwsA(isA<Fido2ProtocolException>()),
      );
    });
  });

  test('PINs follow the CTAP2 length rules', () {
    expect(checkPin(null), PinProblem.missing);
    expect(checkPin(''), PinProblem.missing);
    expect(checkPin('123'), PinProblem.tooShort);
    expect(checkPin('1234'), isNull);
    expect(checkPin('ü' * 32), PinProblem.tooLong);
    expect(checkPin('a' * 63), isNull);
  });

  group('assertion request and answer', () {
    AssertionRequest request() => AssertionRequest.build(
      instanceUrl: 'https://xguard.example.com',
      challenge: 'q83vEjRWeJA-_q83vEjRWeJA',
      credentialIds: ['AQID', 'BAUG'],
    );

    test('binds the hash to the instance origin', () {
      final built = request();
      expect(built.relyingParty.id, 'xguard.example.com');
      expect(
        built.clientDataHash,
        clientDataHash(
          ClientDataType.get,
          'q83vEjRWeJA-_q83vEjRWeJA',
          'https://xguard.example.com',
        ),
      );
      expect(built.credentialIds, [
        [1, 2, 3],
        [4, 5, 6],
      ]);
    });

    test('accepts an answer for this site with presence and verification', () {
      checkAssertion(
        request: request(),
        authenticatorData: authData('xguard.example.com'),
        signature: [1, 2, 3],
        credentialId: [4, 5, 6],
      );
    });

    test('refuses answers for another site, without UV, or another key', () {
      void refused(
        List<int> data, {
        List<int> credential = const [1, 2, 3],
        List<int> signature = const [1],
      }) => expect(
        () => checkAssertion(
          request: request(),
          authenticatorData: data,
          signature: signature,
          credentialId: credential,
        ),
        throwsA(isA<Fido2ProtocolException>()),
      );

      refused(authData('evil.example.com'));
      refused(authData('xguard.example.com', flags: 0x01));
      refused(authData('xguard.example.com', flags: 0x04));
      refused(authData('xguard.example.com'), credential: [9]);
      refused(authData('xguard.example.com'), signature: []);
      refused(authData('xguard.example.com').sublist(0, 36));
    });
  });
}
