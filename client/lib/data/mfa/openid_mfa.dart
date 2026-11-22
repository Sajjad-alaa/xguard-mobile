import 'dart:async';
import 'dart:io';

import 'package:clock/clock.dart';
import 'package:dio/dio.dart';
import 'package:mobile/data/mfa/mfa_flow.dart';
import 'package:mobile/open/api.dart';

/// How often Edge is asked whether the browser sign-in finished. The same as
/// the desktop client.
const Duration openIdPollInterval = Duration(seconds: 5);

/// How long the user has to sign in at the provider.
const Duration openIdPollTimeout = Duration(minutes: 5);

/// Network errors tolerated in a row while polling: the phone switches
/// networks or suspends the app while the browser is in front.
const int openIdMaxNetworkErrors = 3;

class OpenIdUrlException implements Exception {
  final String message;

  const OpenIdUrlException(this.message);

  @override
  String toString() => 'OpenIdUrlException: $message';
}

bool _isLoopback(String host) {
  if (host == 'localhost') return true;
  final address = InternetAddress.tryParse(host);
  return address != null && address.isLoopback;
}

/// The browser URL of Edge's OpenID MFA page: `<edge>/openid/mfa`, keeping any
/// path prefix of the Edge URL, with the session token and (for multi-step
/// sessions) the attempt ID Core binds the browser sign-in to. Only an HTTPS
/// Edge URL (plain HTTP only to loopback) without credentials is accepted, so
/// the session token never travels in the clear or to a URL the user typed
/// credentials into.
Uri buildOpenIdMfaUrl(String proxyUrl, String token, String? stepAttemptId) {
  final Uri base;
  try {
    base = Uri.parse(proxyUrl.trim());
  } on FormatException {
    throw const OpenIdUrlException('the Edge URL is invalid');
  }
  final secure =
      base.scheme == 'https' ||
      (base.scheme == 'http' && _isLoopback(base.host));
  if (!secure || base.host.isEmpty || base.userInfo.isNotEmpty) {
    throw const OpenIdUrlException('the Edge URL is not an HTTPS URL');
  }
  if (token.isEmpty) {
    throw const OpenIdUrlException('the MFA session has no token');
  }
  final segments = [
    ...base.pathSegments.where((segment) => segment.isNotEmpty),
    'openid',
    'mfa',
  ];
  return base.replace(
    pathSegments: segments,
    queryParameters: {
      'token': token,
      if (stepAttemptId != null && stepAttemptId.isNotEmpty)
        'step_attempt_id': stepAttemptId,
    },
    fragment: null,
  ).removeFragment();
}

sealed class OpenIdPollOutcome {
  const OpenIdPollOutcome();
}

/// The server moved on: the next step, or the whole flow completed.
final class OpenIdPollFinished extends OpenIdPollOutcome {
  final MfaStepProgress progress;

  const OpenIdPollFinished(this.progress);
}

final class OpenIdPollFailed extends OpenIdPollOutcome {
  final Object error;

  const OpenIdPollFailed(this.error);
}

final class OpenIdPollTimedOut extends OpenIdPollOutcome {
  const OpenIdPollTimedOut();
}

final class OpenIdPollCancelled extends OpenIdPollOutcome {
  const OpenIdPollCancelled();
}

bool _isNetworkError(Object error) =>
    (error is MfaRequestException && error.isNetworkError) ||
    (error is DioException && error.response == null) ||
    error is SocketException ||
    error is TimeoutException;

/// Waits for the browser sign-in: asks Edge (through [poll]) at a fixed
/// interval until the step advances or completes, the time runs out, an error
/// ends the session, or the user cancels. One request is in flight at a time;
/// [pollNow] (the app came back to the foreground) skips the wait.
class OpenIdMfaPoller {
  final Future<MfaStepProgress> Function() poll;
  final Duration interval;
  final Duration timeout;
  final int maxNetworkErrors;

  bool _cancelled = false;
  bool _running = false;
  Completer<void>? _wake;
  Timer? _timer;

  OpenIdMfaPoller({
    required this.poll,
    this.interval = openIdPollInterval,
    this.timeout = openIdPollTimeout,
    this.maxNetworkErrors = openIdMaxNetworkErrors,
  });

  bool get isRunning => _running;

  Future<OpenIdPollOutcome> run() async {
    if (_running) throw StateError('OpenID MFA polling is already running');
    _running = true;
    final deadline = clock.now().add(timeout);
    var networkErrors = 0;
    try {
      while (true) {
        if (_cancelled) return const OpenIdPollCancelled();
        if (!clock.now().isBefore(deadline)) return const OpenIdPollTimedOut();
        try {
          final progress = await poll();
          if (_cancelled) return const OpenIdPollCancelled();
          networkErrors = 0;
          if (progress is! MfaStepAwaiting) {
            return OpenIdPollFinished(progress);
          }
        } catch (error) {
          if (_cancelled) return const OpenIdPollCancelled();
          if (!_isNetworkError(error) || ++networkErrors > maxNetworkErrors) {
            return OpenIdPollFailed(error);
          }
        }
        await _sleep(_remaining(deadline));
      }
    } finally {
      _running = false;
      _timer?.cancel();
      _timer = null;
      _wake = null;
    }
  }

  Duration _remaining(DateTime deadline) {
    final left = deadline.difference(clock.now());
    if (left.isNegative) return Duration.zero;
    return left < interval ? left : interval;
  }

  Future<void> _sleep(Duration duration) {
    final wake = Completer<void>();
    _wake = wake;
    _timer = Timer(duration, () {
      if (!wake.isCompleted) wake.complete();
    });
    return wake.future;
  }

  void _wakeUp() {
    _timer?.cancel();
    final wake = _wake;
    if (wake != null && !wake.isCompleted) wake.complete();
  }

  /// Polls at once instead of waiting for the interval.
  void pollNow() => _wakeUp();

  void cancel() {
    _cancelled = true;
    _wakeUp();
  }
}
