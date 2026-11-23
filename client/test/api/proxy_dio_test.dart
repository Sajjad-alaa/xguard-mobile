import 'package:dio/dio.dart';
import 'package:dio_cookie_manager/dio_cookie_manager.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/data/client_identity.dart';
import 'package:mobile/open/api.dart';
import 'package:mobile/open/client_headers_interceptor.dart';
import 'package:talker_dio_logger/talker_dio_logger.dart';

const _facts = DevicePlatformFacts(
  kind: PlatformKind.android,
  osFamily: 'android',
  osType: 'Android',
  osName: '14',
  osVersion: '14',
);

void main() {
  setUpAll(TestWidgetsFlutterBinding.ensureInitialized);

  late Dio dio;

  setUp(() {
    dio = buildProxyDio(
      identity: ClientIdentitySource(
        () async => ClientIdentity(version: '1.6.0', facts: _facts),
      ),
      adapter: _NoopAdapter(),
    );
  });

  test('the header interceptor runs before the cookie manager and logger', () {
    final header = dio.interceptors.indexWhere(
      (i) => i is ClientHeadersInterceptor,
    );
    final cookies = dio.interceptors.indexWhere((i) => i is CookieManager);
    final logger = dio.interceptors.indexWhere((i) => i is TalkerDioLogger);

    expect(header, greaterThanOrEqualTo(0));
    expect(header, lessThan(cookies));
    expect(cookies, lessThan(logger));
  });

  test('exactly one header interceptor is installed', () {
    expect(
      dio.interceptors.whereType<ClientHeadersInterceptor>(),
      hasLength(1),
    );
  });

  test('requests carrying secrets are excluded from Dio logs', () {
    final logger = dio.interceptors.whereType<TalkerDioLogger>().single;
    final settings = logger.settings;

    for (final path in [
      'https://proxy.example/api/v1/enrollment/start',
      'https://proxy.example/api/v1/enrollment/create_device',
      'https://proxy.example/api/v1/client-mfa/start',
      'https://proxy.example/api/v1/client-mfa/finish',
      'https://proxy.example/api/v1/client-mfa/finish-remote',
      'https://proxy.example/api/v1/mfa-flow/start',
      'https://proxy.example/api/v1/mfa-flow/step-start',
      'https://proxy.example/api/v1/mfa-flow/step-finish',
      'https://proxy.example/api/v1/mfa-flow/approve',
      // The polling token and the posture-connect preshared key.
      'https://proxy.example/api/v1/poll',
      'https://proxy.example/edge/api/v1/posture/connect',
    ]) {
      final request = RequestOptions(path: path);
      expect(settings.requestFilter!(request), isFalse);
      expect(
        settings.responseFilter!(Response(requestOptions: request)),
        isFalse,
      );
      expect(
        settings.errorFilter!(DioException(requestOptions: request)),
        isFalse,
      );
    }

    final otherRequest = RequestOptions(
      path: 'https://proxy.example/api/v1/info',
    );
    expect(settings.requestFilter!(otherRequest), isTrue);
  });

  test('validatedProxyUri enforces HTTPS or loopback HTTP without userinfo', () {
    expect(
      validatedProxyUri(
        Uri.parse('https://proxy.example/edge/?a=1#frag'),
        ['api', 'v1', 'client-mfa', 'start'],
      ).toString(),
      'https://proxy.example/edge/api/v1/client-mfa/start',
    );
    expect(
      validatedProxyUri(
        Uri.parse('http://127.0.0.1:8080/p'),
        ['api', 'v1', 'client-mfa', 'start'],
      ).toString(),
      'http://127.0.0.1:8080/p/api/v1/client-mfa/start',
    );
    for (final bad in [
      'http://proxy.example',
      'https://user:pass@proxy.example',
      'ftp://proxy.example',
    ]) {
      expect(
        () => validatedProxyUri(Uri.parse(bad), ['api', 'v1', 'poll']),
        throwsA(isA<FormatException>()),
        reason: bad,
      );
    }
  });

  test('base options carry no capability headers and disable redirects', () {
    expect(dio.options.headers.containsKey(clientVersionHeader), isFalse);
    expect(dio.options.headers.containsKey(clientPlatformHeader), isFalse);
    expect(dio.options.followRedirects, isFalse);
    expect(dio.options.maxRedirects, 0);
  });
}

class _NoopAdapter implements HttpClientAdapter {
  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<List<int>>? requestStream,
    Future<void>? cancelFuture,
  ) async => ResponseBody.fromString('{}', 200);

  @override
  void close({bool force = false}) {}
}
