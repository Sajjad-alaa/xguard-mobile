import 'dart:async';
import 'dart:io';

import 'package:cookie_jar/cookie_jar.dart';
import 'package:dio/dio.dart';
import 'package:dio_cookie_manager/dio_cookie_manager.dart';
import 'package:flutter/foundation.dart';
import 'package:mobile/data/client_identity.dart';
import 'package:mobile/data/config_sync/config_sync.dart';
import 'package:mobile/data/db/enums.dart';
import 'package:mobile/data/proxy/config.dart';
import 'package:mobile/data/proxy/enrollment.dart';
import 'package:mobile/data/proxy/mfa.dart';
import 'package:mobile/data/proxy/mfa_flow.dart' as wire;
import 'package:mobile/data/posture/posture.dart';
import 'package:mobile/open/client_headers_interceptor.dart';
import 'package:native_dio_adapter/native_dio_adapter.dart';
import 'package:talker_dio_logger/talker_dio_logger.dart';

import '../logging.dart';

const _apiV1Segments = ['api', 'v1'];
final enrollmentPathSegments = ['api', 'v1', 'enrollment'];
final mfaPathSegments = ['api', 'v1', 'client-mfa'];
final mfaFlowPathSegments = [..._apiV1Segments, 'mfa-flow'];
final posturePathSegments = [..._apiV1Segments, 'posture'];

const _iosConnectionLostCode = '-1005';

bool _isLoopbackHost(String host) {
  if (host.toLowerCase() == 'localhost') return true;
  final address = InternetAddress.tryParse(host);
  return address != null && address.isLoopback;
}

/// Resolves [suffix] against [url] only when [url] is HTTPS (or plain HTTP to a
/// loopback host), has a host, and carries no userinfo. Existing non-empty path
/// segments are kept as a prefix and query/fragment are stripped.
@visibleForTesting
Uri validatedProxyUri(Uri url, List<String> suffix) {
  final secure =
      url.scheme == 'https' ||
      (url.scheme == 'http' && _isLoopbackHost(url.host));
  if (!secure || url.host.isEmpty || url.userInfo.isNotEmpty) {
    throw const FormatException('Invalid proxy URL');
  }
  return Uri(
    scheme: url.scheme,
    host: url.host,
    port: url.hasPort ? url.port : null,
    pathSegments: [
      ...url.pathSegments.where((segment) => segment.isNotEmpty),
      ...suffix,
    ],
  );
}

bool _isMfaEndpoint(Uri uri) =>
    uri.pathSegments.contains(mfaPathSegments.last) ||
    uri.pathSegments.contains(mfaFlowPathSegments.last);

/// Requests that carry secrets (enrollment tokens, MFA proofs, polling tokens,
/// preshared keys) are never logged, not even in debug builds.
bool _isSecretEndpoint(Uri uri) {
  final segments = uri.pathSegments;
  final last = segments.isEmpty ? '' : segments.last;
  return _isMfaEndpoint(uri) ||
      segments.contains(enrollmentPathSegments.last) ||
      last == 'poll' ||
      (last == 'connect' && segments.contains(posturePathSegments.last));
}

/// Throws [PostureRejectedException] when [error] is Core refusing the device
/// for its posture (403 with `code: posture_rejected`).
void _throwIfPostureRejected(DioException error) {
  final response = error.response;
  if (isPostureRejection(response?.statusCode, response?.data)) {
    throw PostureRejectedException(postureRejectionReasons(response?.data));
  }
}

class MfaMethodNotAvailableException implements Exception {
  final MfaMethod method;

  const MfaMethodNotAvailableException(this.method);

  @override
  String toString() =>
      'Requested MFA method is not available on the account: ${method.toReadableString()}';
}

enum MfaRequestFailure {
  network,
  policyDenied,
  attemptLimit,
  sessionExpired,
  staleAttempt,
  notReady,
  server,
}

class MfaRequestException implements Exception {
  final String operation;
  final int? statusCode;
  final MfaRequestFailure failure;

  const MfaRequestException(
    this.operation, {
    this.statusCode,
    this.failure = MfaRequestFailure.server,
  });

  bool get isNetworkError => failure == MfaRequestFailure.network;

  @override
  String toString() => statusCode == null
      ? '$operation failed'
      : '$operation failed. Status: $statusCode';
}

MfaRequestFailure? _mfaResponseFailure(
  DioException error, {
  bool emptyForbiddenIsAttemptLimit = false,
}) {
  final response = error.response;
  final data = response?.data;
  final message = data is Map ? data['error'] : null;

  if (response?.statusCode == 400 && message == 'login session not found') {
    return MfaRequestFailure.sessionExpired;
  }
  if (response?.statusCode == 401 && message == 'invalid token') {
    return MfaRequestFailure.sessionExpired;
  }
  if (response?.statusCode == 400 && message == 'stale MFA attempt') {
    return MfaRequestFailure.staleAttempt;
  }
  if (response?.statusCode == 403 &&
      (message ==
              'Too many failed MFA attempts. Please try connecting again.' ||
          (emptyForbiddenIsAttemptLimit && (data == null || data == '')))) {
    return MfaRequestFailure.attemptLimit;
  }
  return null;
}

MfaRequestException _mfaRequestException(
  String operation,
  DioException error, {
  Map<int, MfaRequestFailure> statusFailures = const {},
  bool classifyResponse = false,
  bool emptyForbiddenIsAttemptLimit = false,
}) {
  final statusCode = error.response?.statusCode;
  final networkError =
      error.response == null &&
      (error.type == DioExceptionType.connectionError ||
          error.type == DioExceptionType.connectionTimeout ||
          (error.error?.toString().contains(_iosConnectionLostCode) ?? false) ||
          (error.message?.contains(_iosConnectionLostCode) ?? false));
  return MfaRequestException(
    operation,
    statusCode: statusCode,
    failure: networkError
        ? MfaRequestFailure.network
        : (classifyResponse
                  ? _mfaResponseFailure(
                      error,
                      emptyForbiddenIsAttemptLimit:
                          emptyForbiddenIsAttemptLimit,
                    )
                  : null) ??
              statusFailures[statusCode] ??
              MfaRequestFailure.server,
  );
}

enum ProxyTlsFailure { untrusted, expired, hostnameMismatch, other }

class ProxyTlsException implements Exception {
  final ProxyTlsFailure failure;
  final Object? cause;

  const ProxyTlsException(this.failure, {this.cause});

  @override
  String toString() =>
      'TLS connection to proxy failed (${failure.name}): $cause';
}

final _nsUrlErrorCode = RegExp(r'domain=NSURLErrorDomain, code=(-\d+)');

ProxyTlsFailure? _tlsFailure(DioException error) {
  if (error.response != null) return null;
  final cause = error.error?.toString() ?? '';

  if (cause.contains('net::ERR_CERT_AUTHORITY_INVALID')) {
    return .untrusted;
  }
  if (cause.contains('net::ERR_CERT_DATE_INVALID')) {
    return .expired;
  }
  if (cause.contains('net::ERR_CERT_COMMON_NAME_INVALID')) {
    return .hostnameMismatch;
  }
  if (cause.contains('net::ERR_CERT_') ||
      cause.contains('net::ERR_SSL_') ||
      cause.contains('net::ERR_BAD_SSL_CLIENT_AUTH_CERT')) {
    return .other;
  }

  // iOS reports a hostname mismatch as -1202 too
  return switch (_nsUrlErrorCode.firstMatch(cause)?.group(1)) {
    '-1202' || '-1203' => .untrusted,
    '-1201' || '-1204' => .expired,
    '-1200' || '-1205' || '-1206' => .other,
    _ => null,
  };
}

const _startFailures = {
  403: MfaRequestFailure.policyDenied,
  428: MfaRequestFailure.notReady,
};

/// The only sanctioned path to the proxy. Every request through this Dio is
/// held by [ClientHeadersInterceptor] until the client identity is known.
@visibleForTesting
Dio buildProxyDio({
  required ClientIdentitySource identity,
  HttpClientAdapter? adapter,
}) {
  final dio = Dio(
    BaseOptions(
      responseType: ResponseType.json,
      connectTimeout: Duration(seconds: 20),
      receiveTimeout: Duration(seconds: 60),
    ),
  );
  dio.httpClientAdapter = adapter ?? NativeAdapter();
  dio.interceptors.addAll([
    ClientHeadersInterceptor(identity),
    CookieManager(CookieJar()),
    TalkerDioLogger(
      talker: talker,
      settings: TalkerDioLoggerSettings(
        printRequestHeaders: !kReleaseMode,
        printRequestData: !kReleaseMode,
        printResponseData: !kReleaseMode,
        printErrorData: !kReleaseMode,
        requestFilter: (request) => !_isSecretEndpoint(request.uri),
        responseFilter: (response) =>
            !_isSecretEndpoint(response.requestOptions.uri),
        errorFilter: (error) => !_isSecretEndpoint(error.requestOptions.uri),
      ),
    ),
  ]);
  return dio;
}

class ProxyApi {
  static final ProxyApi _instance = ProxyApi._internal();

  factory ProxyApi() => _instance;

  final Dio _dio;

  ProxyApi._internal() : _dio = buildProxyDio(identity: clientIdentity);

  @visibleForTesting
  ProxyApi.forTesting(this._dio);

  /// Polls Edge for the configuration of the device holding [token]. Sends
  /// [revision] (the one applied last) so an unchanged configuration costs one
  /// small response. Redirects are never followed, so the token cannot be sent
  /// to another host; the response size and time are bounded.
  Future<ConfigPoll> fetchConfig(
    String proxyUrl,
    String token, {
    String? revision,
  }) async {
    final endpoint = pollUri(proxyUrl);
    final cancel = CancelToken();
    final Response<dynamic> response;
    try {
      response = await _dio.postUri(
        endpoint,
        data: pollRequestBody(token, revision),
        cancelToken: cancel,
        options: Options(
          followRedirects: false,
          maxRedirects: 0,
          sendTimeout: pollTimeout,
          receiveTimeout: pollTimeout,
          validateStatus: (_) => true,
        ),
        onReceiveProgress: (received, total) {
          if (received > maxPollResponseBytes ||
              total > maxPollResponseBytes) {
            cancel.cancel('response too large');
          }
        },
      ).timeout(pollTimeout + const Duration(seconds: 5));
    } on DioException catch (e) {
      if (CancelToken.isCancel(e)) {
        throw const ConfigPollException(
          PollFailure.server,
          'response too large',
        );
      }
      throw ConfigPollException(PollFailure.network, e.type.name);
    } on TimeoutException {
      throw const ConfigPollException(PollFailure.network, 'timeout');
    }
    final status = response.statusCode;
    if (status != 200) {
      throw ConfigPollException(failureForStatus(status), 'HTTP $status');
    }
    return parsePollResponse(response.data);
  }

  /// Posture-only connect for a location without MFA: sends the facts with the
  /// device's polling token and returns the session's preshared key.
  Future<String> postureConnect(
    Uri url, {
    required int locationId,
    required String pubkey,
    required String token,
    required DevicePostureFacts posture,
  }) async {
    final endpoint = validatedProxyUri(url, [
      ...posturePathSegments,
      'connect',
    ]);
    final Response<dynamic> response;
    try {
      response = await _dio.postUri(
        endpoint,
        data: {
          'location_id': locationId,
          'pubkey': pubkey,
          'token': token,
          'posture': posture.toJson(),
        },
        options: Options(followRedirects: false, maxRedirects: 0),
      );
    } on DioException catch (e) {
      _throwIfPostureRejected(e);
      throw _mfaRequestException(
        'Posture check',
        e,
        statusFailures: const {403: MfaRequestFailure.policyDenied},
      );
    }
    final data = response.data;
    final key = data is Map ? data['preshared_key'] : null;
    if (key is! String) {
      throw const FormatException('Invalid posture connect response');
    }
    return key;
  }

  Future<EnrollmentStartResponse> startEnrollment(
    Uri url,
    EnrollmentStartRequest data,
  ) async {
    final endpoint = validatedProxyUri(url, [
      ...enrollmentPathSegments,
      'start',
    ]);
    try {
      final requestBody = data.toJson();
      final response = await _dio.postUri(endpoint, data: requestBody);
      return EnrollmentStartResponse.fromJson(response.data);
    } on DioException catch (e) {
      if (e.response != null) {
        throw HttpException(
          'Failed to start enrollment. Status: ${e.response?.statusCode} Body: ${e.response?.data}',
        );
      }
      if (_tlsFailure(e) case final failure?) {
        throw ProxyTlsException(failure, cause: e.error);
      }
      rethrow;
    } catch (e) {
      throw FormatException(
        "Invalid JSON sent by start enrollment endpoint! Error: $e",
      );
    }
  }

  Future<CreateDeviceResponse> createDevice(
    Uri url,
    CreateDeviceRequest data,
  ) async {
    final endpoint = validatedProxyUri(url, [
      ...enrollmentPathSegments,
      'create_device',
    ]);

    try {
      final response = await _dio.postUri(endpoint, data: data.toJson());
      return CreateDeviceResponse.fromJson(response.data);
    } on DioException catch (e) {
      if (e.response != null) {
        throw HttpException(
          "Failed to create device. Status: ${e.response?.statusCode} Body: ${e.response?.data}",
        );
      }
      if (_tlsFailure(e) case final failure?) {
        throw ProxyTlsException(failure, cause: e.error);
      }
      rethrow;
    } catch (e) {
      throw FormatException(
        "Invalid JSON sent by create device endpoint! Error: $e",
      );
    }
  }

  Future<StartMfaResponse> startMfa(Uri url, StartMfaRequest data) async {
    final endpoint = validatedProxyUri(url, [...mfaPathSegments, 'start']);

    try {
      final response = await _dio.postUri(
        endpoint,
        data: data.toJson(),
        options: Options(followRedirects: false, maxRedirects: 0),
      );
      return StartMfaResponse.fromJson(response.data);
    } on DioException catch (e) {
      final responseData = e.response?.data;
      final dataError = responseData is Map<String, dynamic>
          ? responseData['error']
          : null;
      if (dataError is String &&
          dataError.toLowerCase().trim() ==
              'selected mfa method not available') {
        throw MfaMethodNotAvailableException(data.method);
      }
      _throwIfPostureRejected(e);
      throw _mfaRequestException(
        'MFA start',
        e,
        statusFailures: _startFailures,
      );
    } catch (e) {
      talker.error('Invalid MFA start response: ${e.runtimeType}');
      throw const FormatException('Invalid MFA start response');
    }
  }

  Future<wire.MfaFlowStartResponse> startMfaFlow(
    Uri url,
    wire.MfaFlowStartRequest data,
  ) async {
    final endpoint = validatedProxyUri(url, [
      ...mfaFlowPathSegments,
      'start',
    ]);
    try {
      final response = await _dio.postUri(
        endpoint,
        data: data.toJson(),
        options: Options(followRedirects: false, maxRedirects: 0),
      );
      return wire.MfaFlowStartResponse.fromJson(response.data);
    } on DioException catch (e) {
      _throwIfPostureRejected(e);
      throw _mfaRequestException(
        'MFA flow start',
        e,
        statusFailures: _startFailures,
      );
    } catch (e) {
      talker.error('Invalid MFA flow start response: ${e.runtimeType}');
      throw const FormatException('Invalid MFA flow start response');
    }
  }

  Future<wire.MfaFlowStepStartResponse> startMfaFlowStep(
    Uri url,
    wire.MfaFlowStepStartRequest data,
  ) async {
    final endpoint = validatedProxyUri(url, [
      ...mfaFlowPathSegments,
      'step-start',
    ]);
    try {
      final response = await _dio.postUri(
        endpoint,
        data: data.toJson(),
        options: Options(followRedirects: false, maxRedirects: 0),
      );
      return wire.MfaFlowStepStartResponse.fromJson(response.data);
    } on DioException catch (e) {
      throw _mfaRequestException(
        'MFA flow step start',
        e,
        statusFailures: const {428: MfaRequestFailure.notReady},
      );
    } catch (e) {
      talker.error('Invalid MFA flow step start response: ${e.runtimeType}');
      throw const FormatException('Invalid MFA flow step start response');
    }
  }

  Future<FinishMfaResponse?> finishMfa(
    Uri url,
    FinishMfaRequest data,
  ) async {
    final endpoint = validatedProxyUri(url, [...mfaPathSegments, 'finish']);
    try {
      final response = await _dio.postUri(
        endpoint,
        data: data.toJson(),
        options: Options(
          followRedirects: false,
          maxRedirects: 0,
          validateStatus: (status) =>
              status != null && (status < 400 || status == 428),
        ),
      );
      if (response.statusCode == 428) return null;
      return FinishMfaResponse.fromJson(response.data);
    } on DioException catch (e) {
      _throwIfPostureRejected(e);
      if (e.response?.statusCode == 401 && _mfaResponseFailure(e) == null) {
        throw const MfaCodeRejectedException();
      }
      throw _mfaRequestException('MFA finish', e, classifyResponse: true);
    } catch (e) {
      talker.error('Invalid MFA finish response: ${e.runtimeType}');
      throw const FormatException('Invalid MFA finish response');
    }
  }

  Future<wire.MfaFlowStepFinishResponse> finishMfaFlow(
    Uri url,
    wire.MfaFlowStepFinishRequest data,
  ) async {
    final endpoint = validatedProxyUri(url, [
      ...mfaFlowPathSegments,
      'step-finish',
    ]);
    try {
      final response = await _dio.postUri(
        endpoint,
        data: data.toJson(),
        options: Options(followRedirects: false, maxRedirects: 0),
      );
      return wire.MfaFlowStepFinishResponse.fromJson(response.data);
    } on DioException catch (e) {
      _throwIfPostureRejected(e);
      if (e.response?.statusCode == 401 && _mfaResponseFailure(e) == null) {
        throw const MfaCodeRejectedException();
      }
      throw _mfaRequestException(
        'MFA flow step finish',
        e,
        classifyResponse: true,
        emptyForbiddenIsAttemptLimit: true,
      );
    } catch (e) {
      talker.error('Invalid MFA flow step finish response: ${e.runtimeType}');
      throw const FormatException('Invalid MFA flow step finish response');
    }
  }

  Future<void> finishRemoteMfa(Uri url, FinishMfaRequest data) async {
    final endpoint = validatedProxyUri(url, [
      ...mfaPathSegments,
      'finish-remote',
    ]);
    try {
      await _dio.postUri(
        endpoint,
        data: data.toJson(),
        options: Options(followRedirects: false, maxRedirects: 0),
      );
    } on DioException catch (e) {
      throw _mfaRequestException('Remote MFA finish', e);
    }
  }

  Future<void> approveMfaFlow(Uri url, MfaFlowApproveRequest data) async {
    final endpoint = validatedProxyUri(url, [
      ...mfaFlowPathSegments,
      'approve',
    ]);
    try {
      await _dio.postUri(
        endpoint,
        data: data.toJson(),
        options: Options(followRedirects: false, maxRedirects: 0),
      );
    } on DioException catch (e) {
      throw _mfaRequestException('MFA flow approval', e);
    }
  }

  Future<NetworkInfoResponse> networkInfo(Uri url, String pubKey) async {
    final endpoint = validatedProxyUri(url, [
      ..._apiV1Segments,
      'enrollment',
      'network_info',
    ]);
    final body = {'pubkey': pubKey};
    final response = await _dio.postUri(endpoint, data: body);
    return NetworkInfoResponse.fromJson(response.data);
  }

  Future<void> registerMobileAuth(
    Uri proxyUrl,
    String authPubKey,
    String devicePubKey,
  ) async {
    final endpoint = validatedProxyUri(proxyUrl, [
      ..._apiV1Segments,
      'enrollment',
      'register_mobile',
    ]);
    final requestData = RegisterMobileAuth(
      authPubKey: authPubKey,
      devicePubKey: devicePubKey,
    );
    await _dio.postUri(endpoint, data: requestData.toJson());
  }
}

final proxyApi = ProxyApi();
