// Configuration sync: keeps enrolled instances in line with XGuard without a
// new enrollment. The pure parts (URL rules, response parsing, the per-instance
// schedule and the tunnel plan) live here so they are unit tested; the worker
// that uses them is `sync_service.dart`.
//
// The app polls Edge (`POST <edge>/api/v1/poll`) with the device's polling
// token and the revision it applied last (`InstanceInfoRequest.config_revision`).
// Core answers `not_modified` when nothing changed, or the full configuration
// with its new revision and a suggested interval. Mirrors the desktop client's
// `config_sync` (xguard-client, core/src/config_sync.rs).
import 'dart:io';

import 'package:mobile/data/proxy/config.dart';

/// Interval used when the server suggests none.
const Duration defaultPollInterval = Duration(seconds: 60);

/// Bounds applied to the server's suggestion.
const Duration minPollInterval = Duration(seconds: 30);
const Duration maxPollInterval = Duration(hours: 1);

/// First retry delay after a failure; doubles per consecutive failure.
const Duration backoffStart = Duration(seconds: 30);
const Duration backoffMax = Duration(minutes: 30);

/// After the server refused the device (unknown token, disabled user) or does
/// not serve polling: nothing will change soon, so ask rarely.
const Duration rejectedDelay = Duration(hours: 1);

/// The first poll after start-up waits this long (plus jitter), so the app's
/// start is not slowed down and many devices do not poll at once.
const Duration firstPollMin = Duration(seconds: 2);
const Duration firstPollMax = Duration(seconds: 5);

/// A poll the user or the app asked for waits at least this long after the
/// instance's previous one (Edge allows one poll per 5 s per device).
const Duration minTriggeredGap = Duration(seconds: 10);

/// +/- this fraction of jitter on every delay.
const double jitterFraction = 0.2;

/// Limits on a poll.
const Duration pollTimeout = Duration(seconds: 15);
const int maxPollResponseBytes = 4 * 1024 * 1024;
const int maxRevisionLength = 128;

enum PollFailure {
  /// The server does not serve configuration polling (428, 402).
  unsupported,

  /// The server does not know this device's polling token (401).
  unauthorized,

  /// The server refused the device, for example a disabled user (403).
  forbidden,

  /// Polling too often (429).
  rateLimited,

  /// The Edge URL is not one the token may be sent to.
  invalidUrl,

  /// No polling token stored for the instance.
  missingToken,
  network,
  server,
}

class ConfigPollException implements Exception {
  final PollFailure failure;

  /// Log detail; never contains the token.
  final String? detail;

  const ConfigPollException(this.failure, [this.detail]);

  @override
  String toString() => detail == null
      ? 'ConfigPollException(${failure.name})'
      : 'ConfigPollException(${failure.name}): $detail';
}

bool _isLoopback(String host) {
  if (host.toLowerCase() == 'localhost') return true;
  final address = InternetAddress.tryParse(host);
  return address != null && address.isLoopback;
}

/// The poll endpoint of an Edge URL: HTTPS, or HTTP to loopback; no
/// credentials. Query and fragment are dropped and a path prefix is kept.
Uri pollUri(String proxyUrl) {
  final Uri base;
  try {
    base = Uri.parse(proxyUrl.trim());
  } on FormatException {
    throw const ConfigPollException(PollFailure.invalidUrl);
  }
  final secure =
      base.scheme == 'https' ||
      (base.scheme == 'http' && _isLoopback(base.host));
  if (!secure || base.host.isEmpty || base.userInfo.isNotEmpty) {
    throw const ConfigPollException(PollFailure.invalidUrl);
  }
  return Uri(
    scheme: base.scheme,
    host: base.host,
    port: base.hasPort ? base.port : null,
    pathSegments: [
      ...base.pathSegments.where((segment) => segment.isNotEmpty),
      'api',
      'v1',
      'poll',
    ],
  );
}

/// The request body. The revision is left out when there is none, so older
/// Cores see the request they always got.
Map<String, dynamic> pollRequestBody(String token, String? revision) => {
  'token': token,
  if (revision != null && revision.isNotEmpty) 'config_revision': revision,
};

PollFailure failureForStatus(int? status) => switch (status) {
  401 => PollFailure.unauthorized,
  403 => PollFailure.forbidden,
  429 => PollFailure.rateLimited,
  428 || 402 => PollFailure.unsupported,
  _ => PollFailure.server,
};

sealed class PollOutcome {
  const PollOutcome();
}

final class PollNotModified extends PollOutcome {
  const PollNotModified();
}

final class PollChanged extends PollOutcome {
  final ConfigurationPollResponse config;

  const PollChanged(this.config);
}

class ConfigPoll {
  final PollOutcome outcome;
  final String? revision;
  final Duration? interval;

  const ConfigPoll({required this.outcome, this.revision, this.interval});
}

/// Interprets a 200 response body from Edge.
ConfigPoll parsePollResponse(Object? body) {
  if (body is! Map) {
    throw const ConfigPollException(PollFailure.server, 'not a JSON object');
  }
  final json = Map<String, dynamic>.from(body);
  final rawRevision = json['config_revision'];
  final revision =
      rawRevision is String &&
          rawRevision.isNotEmpty &&
          rawRevision.length <= maxRevisionLength
      ? rawRevision
      : null;
  final rawInterval = json['poll_interval_secs'];
  final interval = rawInterval is int && rawInterval >= 0
      ? Duration(seconds: rawInterval)
      : null;

  if (json['not_modified'] == true) {
    return ConfigPoll(
      outcome: const PollNotModified(),
      revision: revision,
      interval: interval,
    );
  }
  final deviceConfig = json['device_config'];
  if (deviceConfig is! Map) {
    throw const ConfigPollException(
      PollFailure.server,
      'response without a configuration',
    );
  }
  final ConfigurationPollResponse config;
  try {
    config = ConfigurationPollResponse.fromJson(
      Map<String, dynamic>.from(deviceConfig),
    );
  } catch (e) {
    throw ConfigPollException(
      PollFailure.server,
      'invalid configuration (${e.runtimeType})',
    );
  }
  return ConfigPoll(
    outcome: PollChanged(config),
    revision: revision,
    interval: interval,
  );
}

/// What happened to a poll, as far as scheduling is concerned.
sealed class PollAttempt {
  const PollAttempt();

  factory PollAttempt.fromFailure(PollFailure failure) => switch (failure) {
    PollFailure.rateLimited => const PollRateLimited(),
    PollFailure.unauthorized ||
    PollFailure.forbidden ||
    PollFailure.unsupported ||
    PollFailure.invalidUrl ||
    PollFailure.missingToken => const PollRejected(),
    PollFailure.network || PollFailure.server => const PollFailed(),
  };
}

final class PollSucceeded extends PollAttempt {
  final Duration? interval;

  const PollSucceeded([this.interval]);
}

final class PollFailed extends PollAttempt {
  const PollFailed();
}

final class PollRateLimited extends PollAttempt {
  const PollRateLimited();
}

final class PollRejected extends PollAttempt {
  const PollRejected();
}

Duration _clamp(Duration value, Duration min, Duration max) =>
    value < min ? min : (value > max ? max : value);

Duration _scale(Duration value, double factor) =>
    Duration(microseconds: (value.inMicroseconds * factor).round());

/// Applies +/- [jitterFraction] to [base]; [jitterUnit] is in `[0, 1)`.
Duration jittered(Duration base, double jitterUnit) {
  final unit = jitterUnit.isNaN ? 0.5 : jitterUnit.clamp(0.0, 1.0);
  final factor = 1.0 - jitterFraction + 2.0 * jitterFraction * unit;
  final delay = _scale(base, factor);
  return delay < const Duration(seconds: 1)
      ? const Duration(seconds: 1)
      : delay;
}

/// Delay before the first poll after start-up, in [firstPollMin, firstPollMax].
Duration firstPollDelay(double jitterUnit) {
  final unit = jitterUnit.isNaN ? 0.5 : jitterUnit.clamp(0.0, 1.0);
  return firstPollMin + _scale(firstPollMax - firstPollMin, unit);
}

/// Per-instance poll timing with backoff and jitter.
class SyncSchedule {
  int _consecutiveFailures = 0;

  int get consecutiveFailures => _consecutiveFailures;

  Duration nextDelay(PollAttempt attempt, double jitterUnit) {
    final Duration base;
    switch (attempt) {
      case PollSucceeded(:final interval):
        _consecutiveFailures = 0;
        base = _clamp(
          interval ?? defaultPollInterval,
          minPollInterval,
          maxPollInterval,
        );
      case PollFailed():
        _consecutiveFailures++;
        base = _backoff();
      case PollRateLimited():
        _consecutiveFailures++;
        final backoff = _backoff();
        final floor = defaultPollInterval * 2;
        base = backoff > floor ? backoff : floor;
      case PollRejected():
        _consecutiveFailures = 0;
        base = rejectedDelay;
    }
    return jittered(base, jitterUnit);
  }

  Duration _backoff() {
    final exponent = (_consecutiveFailures - 1).clamp(0, 16);
    final delay = backoffStart * (1 << exponent);
    return delay > backoffMax ? backoffMax : delay;
  }
}

/// What the live tunnel needs after its instance's configuration changed.
enum TunnelAction {
  none,

  /// The location is gone.
  disconnect,

  /// Its settings changed and connecting needs no user (no MFA; a posture
  /// check runs again on its own).
  reconnect,

  /// Its settings changed but connecting needs the user (MFA): ask them.
  reconnectByUser,
}

/// Decides what the active tunnel needs. The app runs at most one tunnel.
TunnelAction planTunnelAction({
  required int activeLocationId,
  required Set<int> removedLocationIds,
  required Set<int> tunnelChangedLocationIds,
  required bool trafficPolicyChanged,
  required bool locationExists,
  required bool locationNeedsMfa,
}) {
  if (removedLocationIds.contains(activeLocationId) || !locationExists) {
    return TunnelAction.disconnect;
  }
  if (!tunnelChangedLocationIds.contains(activeLocationId) &&
      !trafficPolicyChanged) {
    return TunnelAction.none;
  }
  return locationNeedsMfa
      ? TunnelAction.reconnectByUser
      : TunnelAction.reconnect;
}
