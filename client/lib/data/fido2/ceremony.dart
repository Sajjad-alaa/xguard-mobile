import 'package:fido2_plugin/fido2_plugin.dart';
import 'package:flutter/foundation.dart';
import 'package:mobile/data/fido2/protocol.dart';
import 'package:mobile/data/mfa/mfa_transport.dart';

/// How long the user has to bring the key to the phone and touch it.
const Duration fido2CeremonyTimeout = Duration(seconds: 60);

/// Security keys are driven through NFC on Android and iOS, and USB on Android.
bool get fido2PlatformSupported =>
    defaultTargetPlatform == TargetPlatform.android ||
    defaultTargetPlatform == TargetPlatform.iOS;

sealed class Fido2Outcome {
  const Fido2Outcome();
}

/// The key signed the challenge; the proof is ready to submit.
final class Fido2Signed extends Fido2Outcome {
  final MfaFido2Credential credential;

  const Fido2Signed(this.credential);
}

enum Fido2ProblemKind {
  pinMissing,
  pinTooShort,
  pinTooLong,
  pinInvalid,
  pinBlocked,
  pinNotSet,
  wrongKey,
  noKeyRegistered,
  nfcDisabled,
  nfcUnavailable,
  unsupportedKey,
  timeout,
  tagLost,
  cancelled,
  busy,
  badChallenge,
  badAssertion,
  unsupportedPlatform,
  unknown,
}

/// Something the user can act on, or a refusal before the key was asked.
final class Fido2Problem extends Fido2Outcome {
  final Fido2ProblemKind kind;

  /// Remaining PIN attempts, when the key reported them.
  final int? pinRetries;

  /// Log detail only, never shown.
  final String? detail;

  const Fido2Problem(this.kind, {this.pinRetries, this.detail});

  /// The user may fix this on the same screen (PIN, tap again, NFC on).
  bool get retryable => switch (kind) {
    Fido2ProblemKind.pinBlocked ||
    Fido2ProblemKind.pinNotSet ||
    Fido2ProblemKind.noKeyRegistered ||
    Fido2ProblemKind.badChallenge ||
    Fido2ProblemKind.unsupportedPlatform => false,
    _ => true,
  };

  String get message => switch (kind) {
    Fido2ProblemKind.pinMissing => 'Enter your security key PIN.',
    Fido2ProblemKind.pinTooShort =>
      'A security key PIN has at least $minPinCodePoints characters.',
    Fido2ProblemKind.pinTooLong => 'This PIN is too long for a security key.',
    Fido2ProblemKind.pinInvalid => switch (pinRetries) {
      null => 'Wrong PIN. Try again.',
      1 => 'Wrong PIN. One attempt left before the key locks.',
      final n => 'Wrong PIN. $n attempts left.',
    },
    Fido2ProblemKind.pinBlocked =>
      'The security key is locked after too many wrong PINs. Reset it, '
          'then register it again from the XGuard desktop client.',
    Fido2ProblemKind.pinNotSet =>
      'This security key has no PIN. XGuard needs a key with a PIN.',
    Fido2ProblemKind.wrongKey =>
      'This security key is not registered for your account. Try another key.',
    Fido2ProblemKind.noKeyRegistered =>
      'No security key is registered for VPN sign-in on your account. '
          'Register one in the XGuard desktop client.',
    Fido2ProblemKind.nfcDisabled => 'Turn on NFC to use your security key.',
    Fido2ProblemKind.nfcUnavailable =>
      'This device cannot reach security keys over NFC. Plug a USB key in, '
          'or use another method.',
    Fido2ProblemKind.unsupportedKey =>
      'This key does not support FIDO2. Use a FIDO2 security key.',
    Fido2ProblemKind.timeout => 'No security key was found in time. Try again.',
    Fido2ProblemKind.tagLost =>
      'The connection to the key was lost. Hold it still against the phone '
          'and try again.',
    Fido2ProblemKind.cancelled => 'Security key verification cancelled.',
    Fido2ProblemKind.busy =>
      'Another security key request is still running. Try again in a moment.',
    Fido2ProblemKind.badChallenge =>
      'The server sent an invalid security key request. Start connecting '
          'again.',
    Fido2ProblemKind.badAssertion =>
      'The security key returned an invalid answer. Try again.',
    Fido2ProblemKind.unsupportedPlatform =>
      'Security keys are not supported on this device.',
    Fido2ProblemKind.unknown => 'The security key failed. Try again.',
  };
}

Fido2Problem fido2ProblemFromException(Fido2Exception e) {
  final kind = switch (e.code) {
    Fido2ErrorCode.nfcUnavailable => Fido2ProblemKind.nfcUnavailable,
    Fido2ErrorCode.nfcDisabled => Fido2ProblemKind.nfcDisabled,
    Fido2ErrorCode.noCredentials => Fido2ProblemKind.wrongKey,
    // Core requires user verification, so the app always sends the PIN; a key
    // asking for one anyway means it was not accepted.
    Fido2ErrorCode.pinRequired => Fido2ProblemKind.pinInvalid,
    Fido2ErrorCode.pinInvalid => Fido2ProblemKind.pinInvalid,
    Fido2ErrorCode.pinBlocked ||
    Fido2ErrorCode.pinAuthBlocked => Fido2ProblemKind.pinBlocked,
    Fido2ErrorCode.pinNotSet => Fido2ProblemKind.pinNotSet,
    Fido2ErrorCode.unsupportedKey => Fido2ProblemKind.unsupportedKey,
    Fido2ErrorCode.cancelled => Fido2ProblemKind.cancelled,
    Fido2ErrorCode.timeout => Fido2ProblemKind.timeout,
    Fido2ErrorCode.tagLost => Fido2ProblemKind.tagLost,
    Fido2ErrorCode.unknown => Fido2ProblemKind.unknown,
  };
  return Fido2Problem(
    kind,
    pinRetries: e.code == Fido2ErrorCode.pinInvalid ? e.pinRetries : null,
    detail: e.message,
  );
}

/// Runs one assertion against a security key. One ceremony at a time across
/// the app: a key answers one request, and the platform readers are shared.
/// The PIN is passed through to the key and never logged or stored.
class Fido2CeremonyRunner {
  final Fido2Plugin plugin;
  final bool Function() platformSupported;

  static bool _running = false;

  Fido2CeremonyRunner({
    this.plugin = const Fido2Plugin(),
    bool Function()? platformSupported,
  }) : platformSupported = platformSupported ?? (() => fido2PlatformSupported);

  @visibleForTesting
  static void resetForTesting() => _running = false;

  Future<Fido2Outcome> run({
    required String instanceUrl,
    required String challenge,
    required List<String> credentialIds,
    required String? pin,
    Duration timeout = fido2CeremonyTimeout,
  }) async {
    if (!platformSupported()) {
      return const Fido2Problem(Fido2ProblemKind.unsupportedPlatform);
    }
    switch (checkPin(pin)) {
      case PinProblem.missing:
        return const Fido2Problem(Fido2ProblemKind.pinMissing);
      case PinProblem.tooShort:
        return const Fido2Problem(Fido2ProblemKind.pinTooShort);
      case PinProblem.tooLong:
        return const Fido2Problem(Fido2ProblemKind.pinTooLong);
      case null:
        break;
    }

    final AssertionRequest request;
    try {
      request = AssertionRequest.build(
        instanceUrl: instanceUrl,
        challenge: challenge,
        credentialIds: credentialIds,
      );
    } on NoCredentialsOffered {
      return const Fido2Problem(Fido2ProblemKind.noKeyRegistered);
    } on Fido2ProtocolException catch (e) {
      return Fido2Problem(Fido2ProblemKind.badChallenge, detail: e.message);
    }

    if (_running) return const Fido2Problem(Fido2ProblemKind.busy);
    _running = true;
    try {
      final Fido2Assertion assertion;
      try {
        assertion = await plugin.getAssertion(
          rpId: request.relyingParty.id,
          clientDataHash: request.clientDataHash,
          allowCredentials: request.credentialIds,
          pin: pin,
          timeout: timeout,
        );
      } on Fido2Exception catch (e) {
        return fido2ProblemFromException(e);
      } catch (e) {
        return Fido2Problem(Fido2ProblemKind.unknown, detail: '$e');
      }

      try {
        checkAssertion(
          request: request,
          authenticatorData: assertion.authenticatorData,
          signature: assertion.signature,
          credentialId: assertion.credentialId,
        );
        return Fido2Signed(
          MfaFido2Credential.fromAssertion(
            signature: assertion.signature,
            authenticatorData: assertion.authenticatorData,
            credentialId: assertion.credentialId,
          ),
        );
      } on Fido2ProtocolException catch (e) {
        return Fido2Problem(Fido2ProblemKind.badAssertion, detail: e.message);
      } on FormatException catch (e) {
        return Fido2Problem(Fido2ProblemKind.badAssertion, detail: e.message);
      }
    } finally {
      _running = false;
    }
  }

  /// Stops a waiting ceremony; the pending [run] returns
  /// [Fido2ProblemKind.cancelled].
  Future<void> cancel() async {
    try {
      await plugin.cancel();
    } catch (_) {
      // Nothing was running, or the plugin is gone with its engine.
    }
  }
}
