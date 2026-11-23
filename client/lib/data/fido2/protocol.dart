// The pure part of a FIDO2 VPN MFA assertion: what goes to the security key
// and what comes back. No platform calls, so all of it is unit tested.
//
// The key signs `authenticatorData || SHA-256(clientData)`. XGuard Core does not
// receive the client data for an assertion; it rebuilds the same canonical JSON
// from the challenge it issued and its own origin. The bytes built here must be
// identical to Core's `fido2::client_data_json` and to the desktop client's
// `security_key::protocol::client_data_json`.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// The WebAuthn limit for a credential ID.
const int maxCredentialIdLength = 1023;

/// More credentials than any user registers; bounds what an Edge can make the
/// app send to a key.
const int maxCredentialIds = 32;

/// Core issues 32-byte challenges (43 base64url characters).
const int minChallengeLength = 16;
const int maxChallengeLength = 128;

/// CTAP2 limits for a PIN: at least 4 code points, at most 63 bytes of UTF-8.
const int minPinCodePoints = 4;
const int maxPinBytes = 63;

/// Length of the RP ID hash at the start of the authenticator data, plus the
/// flags byte and the 4-byte signature counter.
const int minAuthenticatorDataLength = 37;

class Fido2ProtocolException implements Exception {
  final String message;

  const Fido2ProtocolException(this.message);

  @override
  String toString() => 'Fido2ProtocolException: $message';
}

/// Which ceremony client data is for.
enum ClientDataType {
  create('webauthn.create'),
  get('webauthn.get');

  final String wire;

  const ClientDataType(this.wire);
}

/// Canonical client data:
/// `{"type":…,"challenge":…,"origin":…,"crossOrigin":false}`, with the values
/// quoted as JSON strings (the same escaping as serde_json for every string a
/// Rust `&str` can hold).
Uint8List clientDataJson(
  ClientDataType type,
  String challenge,
  String origin,
) {
  final json =
      '{"type":${jsonEncode(type.wire)},'
      '"challenge":${jsonEncode(challenge)},'
      '"origin":${jsonEncode(origin)},'
      '"crossOrigin":false}';
  return Uint8List.fromList(utf8.encode(json));
}

/// `SHA-256(clientData)`, the value handed to the key with CTAP2.
Uint8List clientDataHash(ClientDataType type, String challenge, String origin) =>
    Uint8List.fromList(
      sha256.convert(clientDataJson(type, challenge, origin)).bytes,
    );

/// The relying party and origin of an XGuard instance: its domain and its URL's
/// origin. Always derived from the instance URL the device enrolled with, never
/// from anything Edge sends, so a key only ever signs for that instance.
class RelyingParty {
  final String id;
  final String origin;

  const RelyingParty({required this.id, required this.origin});

  factory RelyingParty.forInstance(String instanceUrl) {
    final Uri uri;
    try {
      uri = Uri.parse(instanceUrl.trim());
    } on FormatException {
      throw const Fido2ProtocolException('the instance URL is invalid');
    }
    if (uri.userInfo.isNotEmpty) {
      throw const Fido2ProtocolException(
        'the instance URL must not contain credentials',
      );
    }
    if (uri.scheme != 'https' && uri.scheme != 'http') {
      throw const Fido2ProtocolException('the instance URL is not HTTP(S)');
    }
    final host = uri.host.toLowerCase();
    if (uri.scheme == 'http' && host != 'localhost') {
      throw const Fido2ProtocolException('the instance URL must use HTTPS');
    }
    if (host.isEmpty || _isIpAddress(host)) {
      throw const Fido2ProtocolException(
        'the instance URL has no domain name',
      );
    }
    // Rust's URL parser turns international names into punycode; this one does
    // not, so such a name would not match what Core expects.
    if (!_asciiDomain.hasMatch(host)) {
      throw const Fido2ProtocolException(
        'the instance domain is not an ASCII host name',
      );
    }
    final defaultPort = uri.scheme == 'https' ? 443 : 80;
    final origin = uri.hasPort && uri.port != defaultPort
        ? '${uri.scheme}://$host:${uri.port}'
        : '${uri.scheme}://$host';
    return RelyingParty(id: host, origin: origin);
  }

  @override
  bool operator ==(Object other) =>
      other is RelyingParty && other.id == id && other.origin == origin;

  @override
  int get hashCode => Object.hash(id, origin);

  @override
  String toString() => 'RelyingParty($id, $origin)';
}

final _asciiDomain = RegExp(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.?$');

/// URL parsers following WHATWG (as Rust's does) read a host whose last label
/// is a number as an IPv4 address, so such hosts are refused here too.
bool _isIpAddress(String host) {
  if (InternetAddress.tryParse(host) != null) return true;
  if (host.startsWith('[')) return true;
  final labels = host.split('.').where((label) => label.isNotEmpty);
  if (labels.isEmpty) return false;
  final last = labels.last;
  return RegExp(r'^(0x[0-9a-f]*|[0-9]+)$').hasMatch(last);
}

final _base64Url = RegExp(r'^[A-Za-z0-9_-]+$');

/// Checks that a challenge is plain base64url of a sensible length.
void validateChallenge(String challenge) {
  if (challenge.length < minChallengeLength ||
      challenge.length > maxChallengeLength ||
      !_base64Url.hasMatch(challenge)) {
    throw const Fido2ProtocolException('the challenge is not base64url');
  }
}

Uint8List _decodeCredentialId(String id) {
  final trimmed = id.replaceFirst(RegExp(r'=+$'), '');
  if (trimmed.isEmpty || !_base64Url.hasMatch(trimmed)) {
    throw const Fido2ProtocolException('a credential ID is not base64url');
  }
  final Uint8List bytes;
  try {
    bytes = base64Url.decode(base64Url.normalize(trimmed));
  } on FormatException {
    throw const Fido2ProtocolException('a credential ID is not base64url');
  }
  if (bytes.isEmpty || bytes.length > maxCredentialIdLength) {
    throw const Fido2ProtocolException(
      'a credential ID has an invalid length',
    );
  }
  return bytes;
}

class NoCredentialsOffered extends Fido2ProtocolException {
  const NoCredentialsOffered()
    : super('the server offered no security key credentials');
}

/// Decodes the base64url credential IDs offered for an assertion.
List<Uint8List> decodeCredentialIds(List<String> ids) {
  if (ids.isEmpty) throw const NoCredentialsOffered();
  if (ids.length > maxCredentialIds) {
    throw const Fido2ProtocolException('too many credential IDs');
  }
  return ids.map(_decodeCredentialId).toList(growable: false);
}

/// Why a PIN cannot be sent to a key.
enum PinProblem { missing, tooShort, tooLong }

/// Null when the PIN can be handed to the key.
PinProblem? checkPin(String? pin) {
  if (pin == null || pin.isEmpty) return PinProblem.missing;
  if (pin.runes.length < minPinCodePoints) return PinProblem.tooShort;
  if (utf8.encode(pin).length > maxPinBytes) return PinProblem.tooLong;
  return null;
}

/// Everything the key needs for one assertion, checked before the key is asked.
class AssertionRequest {
  final RelyingParty relyingParty;
  final String challenge;
  final List<Uint8List> credentialIds;
  final Uint8List clientDataHash;

  const AssertionRequest._({
    required this.relyingParty,
    required this.challenge,
    required this.credentialIds,
    required this.clientDataHash,
  });

  factory AssertionRequest.build({
    required String instanceUrl,
    required String challenge,
    required List<String> credentialIds,
  }) {
    final rp = RelyingParty.forInstance(instanceUrl);
    validateChallenge(challenge);
    final ids = decodeCredentialIds(credentialIds);
    return AssertionRequest._(
      relyingParty: rp,
      challenge: challenge,
      credentialIds: ids,
      clientDataHash: Uint8List.fromList(
        sha256
            .convert(clientDataJson(ClientDataType.get, challenge, rp.origin))
            .bytes,
      ),
    );
  }
}

/// Checks what the key returned before it goes to Edge: the authenticator data
/// must be for this relying party (its first 32 bytes are SHA-256 of the RP ID)
/// and the credential must be one of those offered.
void checkAssertion({
  required AssertionRequest request,
  required List<int> authenticatorData,
  required List<int> signature,
  required List<int> credentialId,
}) {
  if (authenticatorData.length < minAuthenticatorDataLength ||
      authenticatorData.length > 1024) {
    throw const Fido2ProtocolException(
      'the security key returned malformed authenticator data',
    );
  }
  if (signature.isEmpty || signature.length > 512) {
    throw const Fido2ProtocolException(
      'the security key returned a malformed signature',
    );
  }
  final flags = authenticatorData[32];
  if (flags & _userPresent == 0 || flags & _userVerified == 0) {
    throw const Fido2ProtocolException(
      'the security key did not verify the user',
    );
  }
  final rpIdHash = sha256.convert(utf8.encode(request.relyingParty.id)).bytes;
  for (var i = 0; i < 32; i++) {
    if (authenticatorData[i] != rpIdHash[i]) {
      throw const Fido2ProtocolException(
        'the security key signed for another site',
      );
    }
  }
  final offered = request.credentialIds.any(
    (id) => _sameBytes(id, credentialId),
  );
  if (!offered) {
    throw const Fido2ProtocolException(
      'the security key used a credential that was not offered',
    );
  }
}

const int _userPresent = 0x01;
const int _userVerified = 0x04;

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
