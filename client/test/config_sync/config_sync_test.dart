import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:clock/clock.dart';
import 'package:dio/dio.dart';
import 'package:drift/drift.dart' as d;
import 'package:drift/native.dart';
import 'package:fake_async/fake_async.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/data/config_sync/config_sync.dart';
import 'package:mobile/data/config_sync/sync_service.dart';
import 'package:mobile/data/db/database.dart';
import 'package:mobile/data/db/enums.dart';
import 'package:mobile/data/plugin/plugin.dart';
import 'package:mobile/data/proxy/enrollment.dart';
import 'package:mobile/open/api.dart';
import 'package:mobile/open/config_sync_controller.dart';
import 'package:mobile/utils/update_instance.dart';

class _FakeTunnels implements ConfigSyncTunnels {
  PluginTunnelEventData? current;
  int disconnectCount = 0;
  final reconnectCalls =
      <({XGuardInstance instance, Location location, RoutingMethod traffic})>[];
  String? reconnectError;

  @override
  PluginTunnelEventData? get active => current;

  @override
  Future<void> disconnect() async {
    disconnectCount++;
    current = null;
  }

  @override
  Future<String?> reconnect(
    XGuardInstance instance,
    Location location,
    RoutingMethod traffic,
  ) async {
    reconnectCalls.add((
      instance: instance,
      location: location,
      traffic: traffic,
    ));
    return reconnectError;
  }
}

class _ThrowingDisconnectTunnels extends _FakeTunnels {
  @override
  Future<void> disconnect() => Future.error(StateError('plugin failure'));
}

class _FixedRandom implements Random {
  final double value;

  const _FixedRandom(this.value);

  @override
  double nextDouble() => value;

  @override
  bool nextBool() => value >= 0.5;

  @override
  int nextInt(int max) => 0;
}

class _StubAdapter implements HttpClientAdapter {
  RequestOptions? lastRequest;
  String? lastBody;
  int statusCode = 200;
  Object body = '{}';

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    lastRequest = options;
    lastBody = requestStream == null
        ? null
        : utf8.decode(await requestStream.expand((chunk) => chunk).toList());
    final text = body is String ? body as String : jsonEncode(body);
    return ResponseBody.fromString(
      text,
      statusCode,
      headers: {
        Headers.contentTypeHeader: [Headers.jsonContentType],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

Map<String, dynamic> _configPayload({
  String instanceUuid = 'inst-uuid-1',
  String instanceName = 'Office',
  String url = 'https://xguard.example.com',
  String proxyUrl = 'https://edge.example.com',
  int clientTrafficPolicy = 0,
  bool disableTunnels = false,
  int networkId = 11,
  String locationName = 'HQ',
  String endpoint = 'vpn.example.com:51820',
  String? dns = '10.0.0.1',
  int? mtu = 1380,
  bool mfaEnabled = false,
  bool postureCheckRequired = false,
  List<Map<String, dynamic>>? steps,
  int? serviceLocationMode,
}) => {
  'device': {
    'id': 7,
    'name': 'Pixel',
    'pubkey': 'device-pubkey',
    'user_id': 1,
    'created_at': 1700000000,
  },
  'instance': {
    'id': instanceUuid,
    'name': instanceName,
    'url': url,
    'proxy_url': proxyUrl,
    'username': 'alice',
    'enterprise_enabled': true,
    'disable_all_traffic': clientTrafficPolicy == 1,
    'client_traffic_policy': clientTrafficPolicy,
    'disable_tunnels': disableTunnels,
    'mfa_user_state': {
      'configured_methods': [0],
    },
  },
  'configs': [
    {
      'network_id': networkId,
      'network_name': locationName,
      'config': '',
      'endpoint': endpoint,
      'assigned_ip': '10.0.0.2/24',
      'pubkey': 'loc-pubkey-$networkId',
      'allowed_ips': '10.0.0.0/24',
      'dns': dns,
      'mfa_enabled': mfaEnabled,
      'keepalive_interval': 25,
      'location_mfa_mode': mfaEnabled ? 2 : 1,
      'posture_check_required': postureCheckRequired,
      'steps': ?steps,
      'mtu': mtu,
      'service_location_mode': serviceLocationMode,
    },
  ],
};

Future<(XGuardInstance, Location)> _seedInstance(
  AppDatabase db, {
  String uuid = 'inst-uuid-1',
  ClientTrafficPolicy policy = ClientTrafficPolicy.none,
  bool locationMfa = false,
  int? mtu,
}) async {
  final instanceId = await db
      .into(db.xguardInstances)
      .insert(
        XguardInstancesCompanion.insert(
          name: 'Office',
          uuid: uuid,
          url: 'https://xguard.example.com',
          deviceId: 7,
          proxyUrl: 'https://edge.example.com',
          username: 'alice',
          clientTrafficPolicy: d.Value(policy),
          enterpriseEnabled: true,
          pubKey: 'device-pubkey',
          mfaKeysStored: false,
          mfaContract: const d.Value(MfaContract.multiStep),
        ),
      );
  final locationId = await db
      .into(db.locations)
      .insert(
        LocationsCompanion.insert(
          instance: instanceId,
          networkId: 11,
          name: 'HQ',
          address: '10.0.0.2/24',
          pubKey: 'loc-pubkey-11',
          endpoint: 'vpn.example.com:51820',
          allowedIps: '10.0.0.0/24',
          dns: const d.Value('10.0.0.1'),
          mfaEnabled: d.Value(locationMfa),
          keepAliveInterval: 25,
          locationMfaMode: d.Value(
            locationMfa ? LocationMfaMode.internal : LocationMfaMode.disabled,
          ),
          postureCheckRequired: const d.Value(false),
          mtu: d.Value(mtu),
        ),
      );
  final instance = await db.managers.xguardInstances
      .filter((r) => r.id.equals(instanceId))
      .getSingle();
  final location = await db.managers.locations
      .filter((r) => r.id.equals(locationId))
      .getSingle();
  return (instance, location);
}

void main() {
  group('pollUri and request building', () {
    test('accepts HTTPS and loopback HTTP, keeping path prefix', () {
      expect(
        pollUri(' https://edge.example.com/vpn/?a=1#frag ').toString(),
        'https://edge.example.com/vpn/api/v1/poll',
      );
      expect(
        pollUri('https://edge.example.com:8443').toString(),
        'https://edge.example.com:8443/api/v1/poll',
      );
      expect(
        pollUri('http://localhost:8080/edge').toString(),
        'http://localhost:8080/edge/api/v1/poll',
      );
      expect(
        pollUri('http://127.0.0.1:8080').toString(),
        'http://127.0.0.1:8080/api/v1/poll',
      );
      expect(
        pollUri('http://[::1]:8080').toString(),
        'http://[::1]:8080/api/v1/poll',
      );
    });

    test('refuses non-loopback HTTP, credentials, and invalid URLs', () {
      for (final bad in [
        'http://edge.example.com',
        'ftp://edge.example.com',
        'https://user:pass@edge.example.com',
        'https://',
        '://bad',
      ]) {
        expect(
          () => pollUri(bad),
          throwsA(
            isA<ConfigPollException>().having(
              (e) => e.failure,
              'failure',
              PollFailure.invalidUrl,
            ),
          ),
          reason: bad,
        );
      }
    });

    test('omits config_revision when null or empty', () {
      expect(pollRequestBody('tok', null), {'token': 'tok'});
      expect(pollRequestBody('tok', ''), {'token': 'tok'});
      expect(pollRequestBody('tok', 'x1-abc'), {
        'token': 'tok',
        'config_revision': 'x1-abc',
      });
    });

    test('maps HTTP error status codes', () {
      expect(failureForStatus(401), PollFailure.unauthorized);
      expect(failureForStatus(403), PollFailure.forbidden);
      expect(failureForStatus(429), PollFailure.rateLimited);
      expect(failureForStatus(428), PollFailure.unsupported);
      expect(failureForStatus(402), PollFailure.unsupported);
      expect(failureForStatus(500), PollFailure.server);
      expect(failureForStatus(null), PollFailure.server);
    });
  });

  group('parsePollResponse', () {
    test('parses not_modified with bounded revision and interval', () {
      final parsed = parsePollResponse({
        'not_modified': true,
        'config_revision': 'x1-rev-1',
        'poll_interval_secs': 90,
      });
      expect(parsed.outcome, isA<PollNotModified>());
      expect(parsed.revision, 'x1-rev-1');
      expect(parsed.interval, const Duration(seconds: 90));

      final oversized = parsePollResponse({
        'not_modified': true,
        'config_revision': 'r' * (maxRevisionLength + 1),
        'poll_interval_secs': -5,
      });
      expect(oversized.revision, isNull);
      expect(oversized.interval, isNull);
    });

    test('parses full configuration with MTU and traffic policy', () {
      final parsed = parsePollResponse({
        'not_modified': false,
        'config_revision': 'x1-rev-2',
        'poll_interval_secs': 45,
        'device_config': _configPayload(
          clientTrafficPolicy: 2,
          disableTunnels: true,
          mtu: 1420,
        ),
      });
      expect(parsed.outcome, isA<PollChanged>());
      final config = (parsed.outcome as PollChanged).config;
      expect(config.instance?.getPolicy(), ClientTrafficPolicy.forceAllTraffic);
      expect(config.instance?.disableTunnels, isTrue);
      expect(config.configs.single.mtu, 1420);
      expect(parsed.revision, 'x1-rev-2');
    });

    test('rejects non-object or malformed device_config', () {
      expect(
        () => parsePollResponse('not a map'),
        throwsA(isA<ConfigPollException>()),
      );
      expect(
        () => parsePollResponse({'not_modified': false}),
        throwsA(isA<ConfigPollException>()),
      );
      expect(
        () => parsePollResponse({
          'not_modified': false,
          'device_config': {'configs': 'bad'},
        }),
        throwsA(isA<ConfigPollException>()),
      );
    });
  });

  group('ProxyApi.fetchConfig', () {
    test('sends request without redirects and parses response', () async {
      final adapter = _StubAdapter();
      final dio = Dio(BaseOptions(responseType: ResponseType.json))
        ..httpClientAdapter = adapter;
      final api = ProxyApi.forTesting(dio);

      adapter.body = {
        'not_modified': true,
        'config_revision': 'x1-1',
        'poll_interval_secs': 60,
      };
      final result = await api.fetchConfig(
        'https://edge.example.com/p',
        'poll-secret',
        revision: 'x1-1',
      );
      expect(result.outcome, isA<PollNotModified>());
      expect(
        adapter.lastRequest?.uri.toString(),
        'https://edge.example.com/p/api/v1/poll',
      );
      expect(adapter.lastRequest?.followRedirects, isFalse);
      expect(adapter.lastRequest?.maxRedirects, 0);
      expect(jsonDecode(adapter.lastBody!), {
        'token': 'poll-secret',
        'config_revision': 'x1-1',
      });

      adapter.statusCode = 401;
      await expectLater(
        () => api.fetchConfig('https://edge.example.com', 'poll-secret'),
        throwsA(
          isA<ConfigPollException>().having(
            (e) => e.failure,
            'failure',
            PollFailure.unauthorized,
          ),
        ),
      );
    });
  });

  group('SyncSchedule and jitter', () {
    test('clamps server intervals and resets failure count on success', () {
      final schedule = SyncSchedule();
      expect(
        schedule.nextDelay(const PollFailed(), 0.5),
        const Duration(seconds: 30),
      );
      expect(schedule.consecutiveFailures, 1);

      expect(
        schedule.nextDelay(const PollSucceeded(Duration(seconds: 5)), 0.5),
        minPollInterval,
      );
      expect(schedule.consecutiveFailures, 0);
      expect(
        schedule.nextDelay(const PollSucceeded(Duration(hours: 4)), 0.5),
        maxPollInterval,
      );
      expect(
        schedule.nextDelay(const PollSucceeded(null), 0.5),
        defaultPollInterval,
      );
    });

    test('doubles backoff on failures up to backoffMax and handles 429/rejected', () {
      final schedule = SyncSchedule();
      final delays = [
        for (var i = 0; i < 8; i++) schedule.nextDelay(const PollFailed(), 0.5),
      ];
      expect(delays, [
        const Duration(seconds: 30),
        const Duration(seconds: 60),
        const Duration(seconds: 120),
        const Duration(seconds: 240),
        const Duration(seconds: 480),
        const Duration(seconds: 960),
        backoffMax,
        backoffMax,
      ]);

      final rateSchedule = SyncSchedule();
      expect(
        rateSchedule.nextDelay(const PollRateLimited(), 0.5),
        const Duration(seconds: 120),
      );
      expect(
        rateSchedule.nextDelay(const PollRejected(), 0.5),
        rejectedDelay,
      );
      expect(rateSchedule.consecutiveFailures, 0);
    });

    test('applies +/- 20% jitter and bounds firstPollDelay', () {
      expect(
        jittered(const Duration(seconds: 100), 0.0),
        const Duration(seconds: 80),
      );
      expect(
        jittered(const Duration(seconds: 100), 1.0),
        const Duration(seconds: 120),
      );
      expect(
        jittered(const Duration(milliseconds: 500), 0.0),
        const Duration(seconds: 1),
      );
      expect(firstPollDelay(0.0), firstPollMin);
      expect(firstPollDelay(1.0), firstPollMax);
    });
  });

  group('planTunnelAction', () {
    test('plans disconnect, none, reconnect, and reconnectByUser', () {
      expect(
        planTunnelAction(
          activeLocationId: 1,
          removedLocationIds: {1},
          tunnelChangedLocationIds: const {},
          trafficPolicyChanged: false,
          locationExists: true,
          locationNeedsMfa: false,
        ),
        TunnelAction.disconnect,
      );
      expect(
        planTunnelAction(
          activeLocationId: 1,
          removedLocationIds: const {},
          tunnelChangedLocationIds: const {},
          trafficPolicyChanged: false,
          locationExists: false,
          locationNeedsMfa: false,
        ),
        TunnelAction.disconnect,
      );
      expect(
        planTunnelAction(
          activeLocationId: 1,
          removedLocationIds: const {},
          tunnelChangedLocationIds: const {2},
          trafficPolicyChanged: false,
          locationExists: true,
          locationNeedsMfa: false,
        ),
        TunnelAction.none,
      );
      expect(
        planTunnelAction(
          activeLocationId: 1,
          removedLocationIds: const {},
          tunnelChangedLocationIds: const {1},
          trafficPolicyChanged: false,
          locationExists: true,
          locationNeedsMfa: false,
        ),
        TunnelAction.reconnect,
      );
      expect(
        planTunnelAction(
          activeLocationId: 1,
          removedLocationIds: const {},
          tunnelChangedLocationIds: const {},
          trafficPolicyChanged: true,
          locationExists: true,
          locationNeedsMfa: true,
        ),
        TunnelAction.reconnectByUser,
      );
    });
  });

  group('ConfigSyncService', () {
    test(
      'applies MTU/policy changes, enforces minTriggeredGap, and reconnects live tunnel',
      () {
        fakeAsync((async) {
          final db = AppDatabase(NativeDatabase.memory());
          final tunnels = _FakeTunnels();
          final notices = <String>[];
          final sentRevisions = <String?>[];
          late ConfigPoll nextPoll;

          Future<void> run() async {
            final (instance, location) = await _seedInstance(db);
            tunnels.current = PluginTunnelEventData(
              instanceId: instance.id,
              locationId: location.id,
              traffic: RoutingMethod.predefined,
            );
            final service = ConfigSyncService(
              db: db,
              fetch: (proxyUrl, token, revision) async {
                sentRevisions.add(revision);
                return nextPoll;
              },
              readToken: (_) async => 'poll-tok',
              tunnels: tunnels,
              notify: notices.add,
              random: const _FixedRandom(0.5),
            );

            nextPoll = parsePollResponse({
              'not_modified': false,
              'config_revision': 'x1-rev-1',
              'poll_interval_secs': 60,
              'device_config': _configPayload(
                clientTrafficPolicy: 2,
                mtu: 1400,
              ),
            });
            final first = await service.syncNow();
            expect(first[instance.id]?.result, SyncResult.changed);
            expect(
              first[instance.id]?.tunnelAction,
              TunnelAction.reconnect,
            );
            expect(sentRevisions, [null]);
            expect(service.revisionOf(instance.id), 'x1-rev-1');

            final updatedLocation = await db.managers.locations
                .filter((r) => r.id.equals(location.id))
                .getSingle();
            expect(updatedLocation.mtu, 1400);
            final updatedInstance = await db.managers.xguardInstances
                .filter((r) => r.id.equals(instance.id))
                .getSingle();
            expect(
              updatedInstance.clientTrafficPolicy,
              ClientTrafficPolicy.forceAllTraffic,
            );
            expect(tunnels.reconnectCalls.single.location.mtu, 1400);
            expect(
              notices.single,
              'HQ reconnected with its new configuration.',
            );

            // Within minTriggeredGap: skipped.
            async.elapse(const Duration(seconds: 5));
            final skipped = await service.syncNow();
            expect(skipped, isEmpty);
            expect(sentRevisions, hasLength(1));

            // After minTriggeredGap: sends stored revision and handles not_modified.
            async.elapse(const Duration(seconds: 6));
            nextPoll = parsePollResponse({
              'not_modified': true,
              'config_revision': 'x1-rev-1',
              'poll_interval_secs': 60,
            });
            final second = await service.syncNow();
            expect(second[instance.id]?.result, SyncResult.notModified);
            expect(sentRevisions, [null, 'x1-rev-1']);
            expect(
              service.nextDueOf(instance.id),
              clock.now().add(const Duration(seconds: 60)),
            );

            service.dispose();
            await db.close();
          }

          var done = false;
          Object? err;
          run().then(
            (_) => done = true,
            onError: (Object e) {
              err = e;
              done = true;
            },
          );
          async.flushMicrotasks();
          expect(done, isTrue);
          if (err != null) fail('Unexpected error: $err');
        });
      },
    );

    test(
      'skips service locations, disconnects removed active location, and drops revision when apply fails',
      () async {
        final db = AppDatabase(NativeDatabase.memory());
        addTearDown(db.close);
        final tunnels = _FakeTunnels();
        final notices = <String>[];
        final (instance, location) = await _seedInstance(db, locationMfa: true);
        tunnels.current = PluginTunnelEventData(
          instanceId: instance.id,
          locationId: location.id,
          traffic: RoutingMethod.all,
        );

        late ConfigPoll nextPoll;
        final service = ConfigSyncService(
          db: db,
          fetch: (proxyUrl, token, revision) async => nextPoll,
          readToken: (_) async => 'poll-tok',
          tunnels: tunnels,
          notify: notices.add,
          random: const _FixedRandom(0.5),
        );
        addTearDown(service.dispose);

        // Response for another instance: refused, revision cleared.
        nextPoll = parsePollResponse({
          'not_modified': false,
          'config_revision': 'x1-wrong',
          'device_config': _configPayload(instanceUuid: 'other-instance'),
        });
        final wrong = await service.syncNow();
        expect(wrong[instance.id]?.result, SyncResult.failed);
        expect(service.revisionOf(instance.id), isNull);

        // Server removes regular location and sends only a service location.
        nextPoll = parsePollResponse({
          'not_modified': false,
          'config_revision': 'x1-svc',
          'device_config': _configPayload(
            networkId: 99,
            serviceLocationMode: 3,
          ),
        });
        final service2 = ConfigSyncService(
          db: db,
          fetch: (proxyUrl, token, revision) async => nextPoll,
          readToken: (_) async => 'poll-tok',
          tunnels: tunnels,
          notify: notices.add,
          random: const _FixedRandom(0.5),
        );
        addTearDown(service2.dispose);
        final report = await service2.syncNow();
        expect(report[instance.id]?.result, SyncResult.changed);
        expect(report[instance.id]?.tunnelAction, TunnelAction.disconnect);
        expect(tunnels.disconnectCount, 1);
        expect(await db.select(db.locations).get(), isEmpty);
        expect(notices.last, contains('Disconnected'));
      },
    );

    test(
      'notifies user to reconnect when MFA location tunnel changes',
      () async {
        final db = AppDatabase(NativeDatabase.memory());
        addTearDown(db.close);
        final tunnels = _FakeTunnels();
        final notices = <String>[];
        final (instance, location) = await _seedInstance(db, locationMfa: true);
        tunnels.current = PluginTunnelEventData(
          instanceId: instance.id,
          locationId: location.id,
          traffic: RoutingMethod.all,
        );

        final service = ConfigSyncService(
          db: db,
          fetch: (_, _, _) async => parsePollResponse({
            'not_modified': false,
            'config_revision': 'x1-mfa',
            'device_config': _configPayload(
              mfaEnabled: true,
              mtu: 1360,
            ),
          }),
          readToken: (_) async => 'poll-tok',
          tunnels: tunnels,
          notify: notices.add,
          random: const _FixedRandom(0.5),
        );
        addTearDown(service.dispose);

        final report = await service.syncNow();
        expect(report[instance.id]?.result, SyncResult.changed);
      expect(report[instance.id]?.tunnelAction, TunnelAction.reconnectByUser);
        expect(tunnels.reconnectCalls, isEmpty);
        expect(tunnels.disconnectCount, 0);
        expect(notices.single, contains('Reconnect to apply it.'));
      },
    );

    test(
      'disconnects live tunnel when policy tightens on MFA location, pins URLs, clears DNS, and sanitizes MTU',
      () async {
        final db = AppDatabase(NativeDatabase.memory());
        addTearDown(db.close);
        final tunnels = _FakeTunnels();
        final notices = <String>[];
        final (instance, location) = await _seedInstance(db, locationMfa: false);
        tunnels.current = PluginTunnelEventData(
          instanceId: instance.id,
          locationId: location.id,
          traffic: RoutingMethod.all,
        );

        late ConfigPoll nextPoll;
        final service = ConfigSyncService(
          db: db,
          fetch: (_, _, _) async => nextPoll,
          readToken: (_) async => 'poll-tok',
          tunnels: tunnels,
          notify: notices.add,
          random: const _FixedRandom(0.5),
        );
        addTearDown(service.dispose);

        // Tightening MFA on an active non-MFA location disconnects immediately;
        // mismatched server URLs stay pinned, cleared DNS becomes null, and bad MTU is ignored.
        nextPoll = parsePollResponse({
          'not_modified': false,
          'config_revision': 'x1-tight-1',
          'device_config': _configPayload(
            url: 'http://evil.example.com',
            proxyUrl: 'http://evil-edge.example.com',
            dns: null,
            mtu: 10,
            mfaEnabled: true,
          ),
        });
        final first = await service.syncNow();
        expect(first[instance.id]?.result, SyncResult.changed);
        expect(first[instance.id]?.tunnelAction, TunnelAction.reconnectByUser);
        expect(tunnels.disconnectCount, 1);
        expect(tunnels.active, isNull);
        expect(notices.last, contains('Disconnected; reconnect to apply it.'));

        final syncedInstance = await db.managers.xguardInstances
            .filter((r) => r.id.equals(instance.id))
            .getSingle();
        expect(syncedInstance.url, 'https://xguard.example.com');
        expect(syncedInstance.proxyUrl, 'https://edge.example.com');

        final syncedLocation = await db.managers.locations
            .filter((r) => r.id.equals(location.id))
            .getSingle();
        expect(syncedLocation.dns, isNull);
        expect(syncedLocation.mtu, isNull);

        // Posture requirement added on an MFA location also disconnects.
        tunnels.current = PluginTunnelEventData(
          instanceId: instance.id,
          locationId: location.id,
          traffic: RoutingMethod.all,
        );
        await db
            .into(db.locations)
            .insertOnConflictUpdate(
              LocationsCompanion(
                id: d.Value(location.id),
                instance: d.Value(instance.id),
                networkId: d.Value(location.networkId),
                name: d.Value(location.name),
                address: d.Value(location.address),
                pubKey: d.Value(location.pubKey),
                endpoint: d.Value(location.endpoint),
                allowedIps: d.Value(location.allowedIps),
                keepAliveInterval: d.Value(location.keepAliveInterval),
              ),
            );
        nextPoll = parsePollResponse({
          'not_modified': false,
          'config_revision': 'x1-tight-2',
          'device_config': _configPayload(
            mfaEnabled: true,
            postureCheckRequired: true,
            mtu: 10000,
          ),
        });
        final service2 = ConfigSyncService(
          db: db,
          fetch: (_, _, _) async => nextPoll,
          readToken: (_) async => 'poll-tok',
          tunnels: tunnels,
          notify: notices.add,
          random: const _FixedRandom(0.5),
        );
        addTearDown(service2.dispose);
        final second = await service2.syncNow();
        expect(second[instance.id]?.tunnelAction, TunnelAction.reconnectByUser);
        expect(tunnels.disconnectCount, 2);
      },
    );

    test(
      'advances schedule even if tunnels.disconnect throws on policy change',
      () {
        fakeAsync((async) {
          final db = AppDatabase(NativeDatabase.memory());
          final throwingTunnels = _ThrowingDisconnectTunnels();
          final notices = <String>[];

          Future<void> run() async {
            final (instance, location) = await _seedInstance(
              db,
              locationMfa: true,
            );
            throwingTunnels.current = PluginTunnelEventData(
              instanceId: instance.id,
              locationId: location.id,
              traffic: RoutingMethod.all,
            );
            final service = ConfigSyncService(
              db: db,
              fetch: (_, _, _) async => parsePollResponse({
                'not_modified': false,
                'config_revision': 'x1-err',
                'poll_interval_secs': 90,
                'device_config': _configPayload(
                  mfaEnabled: true,
                  clientTrafficPolicy: 1,
                ),
              }),
              readToken: (_) async => 'poll-tok',
              tunnels: throwingTunnels,
              notify: notices.add,
              random: const _FixedRandom(0.5),
            );

            final report = await service.syncNow();
            expect(report[instance.id]?.result, SyncResult.changed);
            expect(
              service.nextDueOf(instance.id),
              clock.now().add(const Duration(seconds: 90)),
            );
            service.dispose();
            await db.close();
          }

          var done = false;
          Object? err;
          run().then(
            (_) => done = true,
            onError: (Object e) {
              err = e;
              done = true;
            },
          );
          async.flushMicrotasks();
          expect(done, isTrue);
          if (err != null) fail('Unexpected error: $err');
        });
      },
    );

    test('formats manualSyncMessage summaries', () {
      expect(manualSyncMessage({}), 'Already up to date.');
      expect(
        manualSyncMessage({
          1: const InstanceSyncReport(SyncResult.notModified),
        }),
        'Already up to date.',
      );
      expect(
        manualSyncMessage({
          1: const InstanceSyncReport(SyncResult.changed),
        }),
        'Configuration updated.',
      );
      expect(
        manualSyncMessage({
          1: const InstanceSyncReport(
            SyncResult.failed,
            failure: PollFailure.unauthorized,
          ),
        }),
        contains('no longer known'),
      );
    });

    test(
      'disconnects live tunnel when step methods narrow from [totp, email] to [fido2]',
      () async {
        final db = AppDatabase(NativeDatabase.memory());
        addTearDown(db.close);
        final tunnels = _FakeTunnels();
        final notices = <String>[];
        final (instance, location) = await _seedInstance(db, locationMfa: true);

        late ConfigPoll nextPoll;
        final service = ConfigSyncService(
          db: db,
          fetch: (_, _, _) async => nextPoll,
          readToken: (_) async => 'poll-tok',
          tunnels: tunnels,
          notify: notices.add,
          random: const _FixedRandom(0.5),
        );
        addTearDown(service.dispose);

        // First set step methods to [totp (0), email (1)] while disconnected.
        nextPoll = parsePollResponse({
          'not_modified': false,
          'config_revision': 'x1-steps-broad',
          'device_config': _configPayload(
            mfaEnabled: true,
            steps: [
              {
                'methods': [
                  {'method': 0, 'configured': true},
                  {'method': 1, 'configured': true},
                ],
              },
            ],
          ),
        });
        await service.syncNow();
        expect(tunnels.disconnectCount, 0);

        // Now connect and narrow allowed methods on step 0 to [fido2 (5)] only.
        tunnels.current = PluginTunnelEventData(
          instanceId: instance.id,
          locationId: location.id,
          traffic: RoutingMethod.all,
        );
        nextPoll = parsePollResponse({
          'not_modified': false,
          'config_revision': 'x1-steps-narrow',
          'device_config': _configPayload(
            mfaEnabled: true,
            steps: [
              {
                'methods': [
                  {'method': 5, 'configured': true},
                ],
              },
            ],
          ),
        });
        final service2 = ConfigSyncService(
          db: db,
          fetch: (_, _, _) async => nextPoll,
          readToken: (_) async => 'poll-tok',
          tunnels: tunnels,
          notify: notices.add,
          random: const _FixedRandom(0.5),
        );
        addTearDown(service2.dispose);
        final report = await service2.syncNow();
        expect(report[instance.id]?.tunnelAction, TunnelAction.reconnectByUser);
        expect(tunnels.disconnectCount, 1);
        expect(tunnels.active, isNull);
        expect(notices.last, contains('Disconnected; reconnect to apply it.'));
      },
    );

    test(
      'applyExternalUpdate disconnects live tunnel after manual refresh tightens policy',
      () async {
        final db = AppDatabase(NativeDatabase.memory());
        addTearDown(db.close);
        final tunnels = _FakeTunnels();
        final notices = <String>[];
        final (instance, location) = await _seedInstance(
          db,
          locationMfa: false,
        );
        tunnels.current = PluginTunnelEventData(
          instanceId: instance.id,
          locationId: location.id,
          traffic: RoutingMethod.all,
        );

        final service = ConfigSyncService(
          db: db,
          fetch: (_, _, _) async => parsePollResponse({'not_modified': true}),
          readToken: (_) async => 'poll-tok',
          tunnels: tunnels,
          notify: notices.add,
          random: const _FixedRandom(0.5),
        );
        addTearDown(service.dispose);

        final payload = _configPayload(mfaEnabled: true);
        final configs = (payload['configs'] as List)
            .map((e) => DeviceConfig.fromJson(e as Map<String, dynamic>))
            .toList();
        final info = InstanceInfo.fromJson(
          payload['instance'] as Map<String, dynamic>,
        );
        final updateResult = await updateInstance(
          db: db,
          instance: instance,
          configs: configs,
          info: info,
        );
        expect(updateResult, isNotNull);
        expect(updateResult!.policyTightened, contains(location.id));

        final action = await service.applyExternalUpdate(
          instance,
          updateResult,
        );
        expect(action, TunnelAction.reconnectByUser);
        expect(tunnels.disconnectCount, 1);
        expect(tunnels.active, isNull);
      },
    );
  });
}
