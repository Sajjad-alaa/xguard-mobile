import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/data/db/enums.dart';
import 'package:mobile/data/mfa/mfa_flow.dart';
import 'package:mobile/data/mfa/mfa_transport.dart';
import 'package:mobile/data/posture/posture.dart';
import 'package:mobile/data/proxy/mfa_flow.dart' as wire;
import 'package:mobile/open/api.dart';
import 'package:mobile/utils/error_handler.dart';

class _RecordingAdapter implements HttpClientAdapter {
  final requests = <RequestOptions>[];
  final bodies = <String>[];
  int statusCode = 200;
  String responseBody = '{}';

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    requests.add(options);
    bodies.add(
      requestStream == null
          ? ''
          : utf8.decode(await requestStream.expand((chunk) => chunk).toList()),
    );
    return ResponseBody.fromString(
      responseBody,
      statusCode,
      headers: {
        Headers.contentTypeHeader: [Headers.jsonContentType],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

void main() {
  group('normalizeOsVersion', () {
    test('keeps 1 to 4 dotted numeric parts and strips suffixes', () {
      expect(normalizeOsVersion('14'), '14');
      expect(normalizeOsVersion('17.5.1'), '17.5.1');
      expect(normalizeOsVersion('1.2.3.4'), '1.2.3.4');
      expect(normalizeOsVersion('1.2.3.4.5'), '1.2.3.4');
      expect(normalizeOsVersion('  15.0.0 (beta) '), '15.0.0');
    });

    test('rejects missing, non-numeric, or oversized versions', () {
      expect(normalizeOsVersion(null), isNull);
      expect(normalizeOsVersion(''), isNull);
      expect(normalizeOsVersion('   '), isNull);
      expect(normalizeOsVersion('Android 14'), isNull);
      expect(normalizeOsVersion('123456.1'), isNull);
    });
  });

  group('normalizePatchDate', () {
    test('accepts valid YYYY-MM-DD dates from year 2000 onwards', () {
      expect(normalizePatchDate('2026-11-01'), '2026-11-01');
      expect(normalizePatchDate(' 2024-02-29 '), '2024-02-29');
      expect(normalizePatchDate('2000-01-01'), '2000-01-01');
    });

    test('rejects invalid calendar dates, wrong formats, and old years', () {
      expect(normalizePatchDate(null), isNull);
      expect(normalizePatchDate(''), isNull);
      expect(normalizePatchDate('2026-02-30'), isNull);
      expect(normalizePatchDate('2025-13-01'), isNull);
      expect(normalizePatchDate('2025-02-29'), isNull);
      expect(normalizePatchDate('1999-12-31'), isNull);
      expect(normalizePatchDate('2026/11/01'), isNull);
    });
  });

  group('diskEncryptedFrom', () {
    test('maps Android encryption statuses and leaves unknown null', () {
      bool? status(int? code) => diskEncryptedFrom(
        PostureProbes(
          os: PostureOs.android,
          androidEncryptionStatus: code,
        ),
      );

      expect(status(AndroidEncryptionStatus.active), isTrue);
      expect(status(AndroidEncryptionStatus.activePerUser), isTrue);
      expect(status(AndroidEncryptionStatus.unsupported), isFalse);
      expect(status(AndroidEncryptionStatus.inactive), isFalse);
      expect(status(AndroidEncryptionStatus.activeDefaultKey), isFalse);
      expect(status(AndroidEncryptionStatus.activating), isNull);
      expect(status(99), isNull);
      expect(status(null), isNull);
    });

    test('maps iOS encryption from device passcode presence', () {
      expect(
        diskEncryptedFrom(
          const PostureProbes(os: PostureOs.ios, deviceSecure: true),
        ),
        isTrue,
      );
      expect(
        diskEncryptedFrom(
          const PostureProbes(os: PostureOs.ios, deviceSecure: false),
        ),
        isFalse,
      );
      expect(
        diskEncryptedFrom(const PostureProbes(os: PostureOs.ios)),
        isNull,
      );
    });

    test('returns null for unspecified or desktop OS probes', () {
      expect(
        diskEncryptedFrom(
          const PostureProbes(
            os: PostureOs.unspecified,
            deviceSecure: true,
            androidEncryptionStatus: AndroidEncryptionStatus.active,
          ),
        ),
        isNull,
      );
    });
  });

  group('buildPostureFacts', () {
    test('builds Android JSON and omits missing and desktop-only facts', () {
      final facts = buildPostureFacts(
        const PostureProbes(
          os: PostureOs.android,
          osVersion: '15 (AP3A)',
          clientVersion: '2.2.0',
          deviceSecure: true,
          androidEncryptionStatus: AndroidEncryptionStatus.activePerUser,
          androidSecurityPatch: '2026-10-05',
        ),
        DateTime.utc(2026, 11, 22, 10, 0, 0),
      );
      final json = facts.toJson();

      expect(json, {
        'os': PostureOs.android.wire,
        'client_version': '2.2.0',
        'collected_at': 1795341600,
        'os_version': '15',
        'os_name': 'Android 15',
        'disk_encrypted': true,
        'screen_lock_enabled': true,
        'security_patch_date': '2026-10-05',
      });
      expect(json.containsKey('device_integrity'), isFalse);
      expect(json.containsKey('kernel_version'), isFalse);
      expect(json.containsKey('firewall_enabled'), isFalse);
      expect(json.containsKey('antivirus_enabled'), isFalse);
    });

    test('builds iOS JSON without Android security patch and omits nulls', () {
      final facts = buildPostureFacts(
        const PostureProbes(
          os: PostureOs.ios,
          osVersion: 'invalid',
          clientVersion: null,
          deviceSecure: null,
          androidSecurityPatch: '2026-10-05',
        ),
        DateTime.utc(2026, 11, 22, 10, 0, 0),
      );
      final json = facts.toJson();

      expect(json, {
        'os': PostureOs.ios.wire,
        'client_version': '0.0.0',
        'collected_at': 1795341600,
        'os_name': 'iOS',
      });
      expect(json.containsKey('os_version'), isFalse);
      expect(json.containsKey('disk_encrypted'), isFalse);
      expect(json.containsKey('screen_lock_enabled'), isFalse);
      expect(json.containsKey('security_patch_date'), isFalse);
    });

    test('strips control characters and caps long client versions', () {
      final longVersion = '1.\n${'2' * 200}';
      final facts = buildPostureFacts(
        PostureProbes(
          os: PostureOs.ios,
          osVersion: '18.1',
          clientVersion: longVersion,
          deviceSecure: false,
        ),
        DateTime.utc(2026, 11, 22, 10, 0, 0),
      );

      expect(facts.clientVersion.length, 128);
      expect(facts.clientVersion, isNot(contains('\n')));
    });
  });

  group('posture rejection and transport', () {
    test('parses posture_rejected code and older prefix format', () {
      expect(
        isPostureRejection(403, {'code': 'posture_rejected', 'error': 'x'}),
        isTrue,
      );
      expect(
        isPostureRejection(403, {
          'error': 'Device posture check failed: OS too old; screen lock off',
        }),
        isTrue,
      );
      expect(
        isPostureRejection(403, {'error': 'Policy denied'}),
        isFalse,
      );
      expect(
        isPostureRejection(401, {'code': 'posture_rejected'}),
        isFalse,
      );

      expect(
        postureRejectionReasons({
          'error': 'Device posture check failed: OS too old\x07;  disk off ; ',
        }),
        'OS too old, disk off',
      );
    });

    test('caps very long rejection reasons and formats user message', () {
      final longError = 'Device posture check failed: ${'a' * 600}';
      final reasons = postureRejectionReasons({'error': longError});
      expect(reasons.length, 513);
      expect(reasons.endsWith('…'), isTrue);

      final ex = PostureRejectedException('screen lock required');
      expect(ErrorHandler.getHumanReadableError(ex), ex.userMessage);
    });

    test('postureConnect posts facts and handles posture_rejected', () async {
      final adapter = _RecordingAdapter();
      final dio = Dio(BaseOptions(responseType: ResponseType.json))
        ..httpClientAdapter = adapter;
      final api = ProxyApi.forTesting(dio);
      final facts = buildPostureFacts(
        const PostureProbes(
          os: PostureOs.android,
          osVersion: '15',
          clientVersion: '2.2.0',
          deviceSecure: true,
          androidEncryptionStatus: AndroidEncryptionStatus.active,
        ),
        DateTime.utc(2026, 11, 22, 10, 0, 0),
      );

      adapter.responseBody = '{"preshared_key":"psk-123"}';
      final key = await api.postureConnect(
        Uri.parse('https://proxy.example/edge'),
        locationId: 11,
        pubkey: 'device-pubkey',
        token: 'poll-token',
        posture: facts,
      );

      expect(key, 'psk-123');
      expect(adapter.requests.single.uri.path, '/edge/api/v1/posture/connect');
      expect(adapter.requests.single.followRedirects, isFalse);
      expect(jsonDecode(adapter.bodies.single), {
        'location_id': 11,
        'pubkey': 'device-pubkey',
        'token': 'poll-token',
        'posture': facts.toJson(),
      });

      adapter.statusCode = 403;
      adapter.responseBody =
          '{"code":"posture_rejected","error":"Device posture check failed: disk encrypted; screen lock"}';
      await expectLater(
        () => api.postureConnect(
          Uri.parse('https://proxy.example/edge'),
          locationId: 11,
          pubkey: 'device-pubkey',
          token: 'poll-token',
          posture: facts,
        ),
        throwsA(
          isA<PostureRejectedException>().having(
            (e) => e.userMessage,
            'userMessage',
            contains('disk encrypted, screen lock'),
          ),
        ),
      );

      adapter.responseBody = '{"error":"Device disabled"}';
      await expectLater(
        () => api.postureConnect(
          Uri.parse('https://proxy.example/edge'),
          locationId: 11,
          pubkey: 'device-pubkey',
          token: 'poll-token',
          posture: facts,
        ),
        throwsA(
          isA<MfaRequestException>().having(
            (e) => e.failure,
            'failure',
            MfaRequestFailure.policyDenied,
          ),
        ),
      );
    });

    test('MFA start sends posture only when provided', () async {
      final adapter = _RecordingAdapter();
      final dio = Dio(BaseOptions(responseType: ResponseType.json))
        ..httpClientAdapter = adapter;
      final api = ProxyApi.forTesting(dio);
      final facts = buildPostureFacts(
        const PostureProbes(
          os: PostureOs.ios,
          osVersion: '18.2',
          clientVersion: '2.2.0',
          deviceSecure: true,
        ),
        DateTime.utc(2026, 11, 22, 10, 0, 0),
      );

      adapter.responseBody =
          '{"outcome":{"Accepted":{"token":"flow-token","first_step":{"step_attempt_id":"attempt-1"}}}}';
      final transport = MfaFlowProxyTransport(
        Uri.parse('https://proxy.example'),
        api: api,
      );
      final controller = MfaFlowController(
        transport: transport,
        plan: const [MfaMethod.totp],
        devicePubkey: 'device-pubkey',
        networkId: 11,
        posture: facts,
      );
      await controller.startStep();

      final sent = jsonDecode(adapter.bodies.single) as Map<String, dynamic>;
      expect(sent['posture'], facts.toJson());

      adapter.statusCode = 403;
      adapter.responseBody =
          '{"code":"posture_rejected","error":"Device posture check failed: OS version"}';
      await expectLater(
        () => api.startMfaFlow(
          Uri.parse('https://proxy.example'),
          wire.MfaFlowStartRequest(
            locationId: 11,
            pubkey: 'device-pubkey',
            selectedMethods: const [MfaMethod.totp],
            posture: facts,
          ),
        ),
        throwsA(
          isA<PostureRejectedException>().having(
            (e) => e.reasons,
            'reasons',
            'OS version',
          ),
        ),
      );
    });
  });
}
