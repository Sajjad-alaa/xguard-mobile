import 'package:mobile/data/db/enums.dart';

/// MFA methods as the proxy sends them, mirroring `MfaMethod` in
/// `proto/common/client_types.proto`. Values this client cannot perform are
/// still represented so that parsing never fails on them.
enum ApiMfaMethod {
  totp(0),
  email(1),
  oidc(2),
  biometric(3),
  mobileApprove(4),
  fido2(5),
  unknown(-1);

  final int value;

  const ApiMfaMethod(this.value);

  static ApiMfaMethod fromWire(int value) =>
      values.firstWhere((m) => m.value == value, orElse: () => unknown);

  static ApiMfaMethod of(MfaMethod method) => switch (method) {
    MfaMethod.totp => totp,
    MfaMethod.email => email,
    MfaMethod.openid => oidc,
    MfaMethod.biometric => biometric,
    MfaMethod.fido2 => fido2,
  };

  /// Null when this client cannot perform the method.
  MfaMethod? get supported => switch (this) {
    totp => MfaMethod.totp,
    email => MfaMethod.email,
    biometric => MfaMethod.biometric,
    // OpenID and FIDO2 MFA are not supported by XGuard.
    oidc || fido2 || mobileApprove || unknown => null,
  };

  /// Row label for a method [supported] cannot map. Supported methods are named
  /// by [MfaMethod.toUiString] instead.
  String get unsupportedLabel => switch (this) {
    mobileApprove => "Mobile approval",
    oidc => "OpenID",
    fido2 => "FIDO2 Security Key",
    _ => "Unsupported method",
  };
}
