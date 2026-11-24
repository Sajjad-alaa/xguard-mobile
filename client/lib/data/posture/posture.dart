// XGuard device posture: the facts the app reports about its own device when it
// connects to a location with posture policies. Mirrors `DevicePostureFacts`
// and `PostureOs` in `proto/common/client_types.proto` (xguard-proto f79e518).
//
// The facts are an attestation, not proof: Core cannot verify them. Missing
// facts are left out of the JSON and Core treats them as unknown, which fails
// every rule that needs them.

/// `PostureOs` on the wire.
enum PostureOs {
  unspecified(0),
  linux(1),
  macos(2),
  windows(3),
  ios(4),
  android(5);

  final int wire;

  const PostureOs(this.wire);
}

/// Core accepts dotted numbers of at most 4 parts of up to 5 digits.
final _dottedVersion = RegExp(r'^\d{1,5}(\.\d{1,5}){0,3}$');
final _patchDate = RegExp(r'^(\d{4})-(\d{2})-(\d{2})$');

/// Longest string fact sent; Core caps them as well.
const int _maxStringFact = 128;

/// `DevicePostureFacts.facts_revision`: the set of facts this app knows how to
/// report. Revision 2 is "every fact the platform can detect": on a phone that
/// is OS version, screen lock, storage encryption and (Android) patch level.
/// Core uses it to tell an app that is too old to report a fact from one that
/// could not determine it.
const int postureFactsRevision = 2;

/// The leading dotted number of a version string ("17.5.1", "14",
/// "15.0.0 (beta)" → "15.0.0"), or null when there is none.
String? normalizeOsVersion(String? raw) {
  if (raw == null) return null;
  final match = RegExp(r'^\s*(\d+(?:\.\d+)*)').firstMatch(raw);
  if (match == null) return null;
  final parts = match.group(1)!.split('.');
  final version = parts.take(4).join('.');
  return _dottedVersion.hasMatch(version) ? version : null;
}

/// A valid `YYYY-MM-DD` Android security patch level, or null.
String? normalizePatchDate(String? raw) {
  if (raw == null) return null;
  final value = raw.trim();
  final match = _patchDate.firstMatch(value);
  if (match == null) return null;
  final year = int.parse(match.group(1)!);
  final month = int.parse(match.group(2)!);
  final day = int.parse(match.group(3)!);
  final date = DateTime.utc(year, month, day);
  if (year < 2000 ||
      date.year != year ||
      date.month != month ||
      date.day != day) {
    return null;
  }
  return value;
}

String? _cleanString(String? value) {
  if (value == null) return null;
  final cleaned = value.replaceAll(RegExp(r'[\x00-\x1F\x7F]'), '').trim();
  if (cleaned.isEmpty) return null;
  return cleaned.length > _maxStringFact
      ? cleaned.substring(0, _maxStringFact)
      : cleaned;
}

class DevicePostureFacts {
  final PostureOs os;
  final String? osVersion;
  final String? osName;
  final String clientVersion;
  final bool? diskEncrypted;
  final bool? screenLockEnabled;
  final bool? deviceIntegrity;
  final String? securityPatchDate;

  /// Unix seconds, client clock.
  final int collectedAt;

  /// See [postureFactsRevision].
  final int factsRevision;

  const DevicePostureFacts({
    required this.os,
    required this.clientVersion,
    required this.collectedAt,
    this.factsRevision = postureFactsRevision,
    this.osVersion,
    this.osName,
    this.diskEncrypted,
    this.screenLockEnabled,
    this.deviceIntegrity,
    this.securityPatchDate,
  });

  /// Facts a phone cannot report reliably are never sent: kernel, firewall,
  /// antivirus and domain do not apply, and neither iOS nor Android tells an
  /// app when the last update was installed (Android's patch level date is
  /// sent instead).
  Map<String, dynamic> toJson() => {
    'os': os.wire,
    'client_version': clientVersion,
    'collected_at': collectedAt,
    'facts_revision': factsRevision,
    'os_version': ?osVersion,
    'os_name': ?osName,
    'disk_encrypted': ?diskEncrypted,
    'screen_lock_enabled': ?screenLockEnabled,
    'device_integrity': ?deviceIntegrity,
    'security_patch_date': ?securityPatchDate,
  };
}

/// What the platform reported, before validation. Every field may be missing.
class PostureProbes {
  final PostureOs os;
  final String? osVersion;
  final String? clientVersion;

  /// Android `KeyguardManager.isDeviceSecure()`, iOS passcode set
  /// (`LAContext.canEvaluatePolicy(.deviceOwnerAuthentication)`).
  final bool? deviceSecure;

  /// Android `DevicePolicyManager.getStorageEncryptionStatus()`.
  final int? androidEncryptionStatus;
  final String? androidSecurityPatch;

  const PostureProbes({
    required this.os,
    this.osVersion,
    this.clientVersion,
    this.deviceSecure,
    this.androidEncryptionStatus,
    this.androidSecurityPatch,
  });
}

/// `DevicePolicyManager.ENCRYPTION_STATUS_*`.
abstract final class AndroidEncryptionStatus {
  static const int unsupported = 0;
  static const int inactive = 1;
  static const int activating = 2;
  static const int active = 3;
  static const int activeDefaultKey = 4;
  static const int activePerUser = 5;
}

/// Storage encryption as the platform reports it.
///
/// - Android: active (3) and file-based per-user (5) are encrypted; encryption
///   with the default key (4, no lock screen credential), inactive and
///   unsupported are not; anything else is unknown. Without a secure lock
///   screen the keys are not protected by a user secret (file-based encryption
///   still reports 5), so a device known to have no lock screen is reported as
///   not encrypted.
/// - iOS: storage is always encrypted in hardware, and Data Protection keys are
///   bound to the passcode, so files are protected exactly when a passcode is
///   set.
bool? diskEncryptedFrom(PostureProbes probes) => switch (probes.os) {
  PostureOs.android => switch (probes.androidEncryptionStatus) {
    AndroidEncryptionStatus.active ||
    AndroidEncryptionStatus.activePerUser => probes.deviceSecure != false,
    AndroidEncryptionStatus.unsupported ||
    AndroidEncryptionStatus.inactive ||
    AndroidEncryptionStatus.activeDefaultKey => false,
    _ => null,
  },
  PostureOs.ios => probes.deviceSecure,
  _ => null,
};

/// Builds the facts sent to Core from what the platform reported.
DevicePostureFacts buildPostureFacts(PostureProbes probes, DateTime now) {
  final version = normalizeOsVersion(probes.osVersion);
  final osName = switch (probes.os) {
    PostureOs.android => version == null ? 'Android' : 'Android $version',
    PostureOs.ios => version == null ? 'iOS' : 'iOS $version',
    _ => null,
  };
  return DevicePostureFacts(
    os: probes.os,
    osVersion: version,
    osName: _cleanString(osName),
    clientVersion: _cleanString(probes.clientVersion) ?? '0.0.0',
    diskEncrypted: diskEncryptedFrom(probes),
    screenLockEnabled: probes.deviceSecure,
    // Verified boot cannot be read without Play Integrity; left unknown.
    deviceIntegrity: null,
    securityPatchDate: probes.os == PostureOs.android
        ? normalizePatchDate(probes.androidSecurityPatch)
        : null,
    collectedAt: now.toUtc().millisecondsSinceEpoch ~/ 1000,
  );
}

const postureRejectedCode = 'posture_rejected';
const postureRejectedPrefix = 'Device posture check failed';

/// Core refused the device for its posture. [reasons] lists the failed checks.
class PostureRejectedException implements Exception {
  final String reasons;

  const PostureRejectedException(this.reasons);

  String get userMessage => reasons.isEmpty
      ? 'This device does not meet the location\'s security requirements.'
      : 'This device does not meet the location\'s security requirements: '
            '$reasons.';

  @override
  String toString() => 'PostureRejectedException: $reasons';
}

/// A 403 with `code: posture_rejected`, or (older Edge) a message starting
/// with the posture prefix.
bool isPostureRejection(int? status, Object? body) {
  if (status != 403 || body is! Map) return false;
  final code = body['code'];
  final message = body['error'];
  return code == postureRejectedCode ||
      (message is String && message.startsWith(postureRejectedPrefix));
}

/// "Device posture check failed: a; b" → "a, b". Capped, control characters
/// removed, since it is shown to the user.
String postureRejectionReasons(Object? body) {
  final message = body is Map ? body['error'] : null;
  if (message is! String) return '';
  var rest = message;
  if (rest.startsWith(postureRejectedPrefix)) {
    rest = rest.substring(postureRejectedPrefix.length);
    rest = rest.replaceFirst(RegExp(r'^\s*:\s*'), '');
  }
  final reasons = rest
      .split(';')
      .map((part) => part.replaceAll(RegExp(r'[\x00-\x1F\x7F]'), '').trim())
      .where((part) => part.isNotEmpty)
      .join(', ');
  return reasons.length > 512 ? '${reasons.substring(0, 512)}…' : reasons;
}
