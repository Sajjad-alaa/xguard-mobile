import 'dart:async';
import 'dart:math';

import 'package:clock/clock.dart';
import 'package:flutter/foundation.dart';
import 'package:mobile/data/config_sync/config_sync.dart';
import 'package:mobile/data/db/database.dart';
import 'package:mobile/data/db/enums.dart';
import 'package:mobile/data/mfa/mfa_plan.dart';
import 'package:mobile/data/plugin/plugin.dart';
import 'package:mobile/logging.dart';
import 'package:mobile/utils/update_instance.dart';

/// The app's live tunnel, as far as config sync is concerned.
abstract class ConfigSyncTunnels {
  PluginTunnelEventData? get active;

  Future<void> disconnect();

  /// Reconnects [location] with its new settings, without the user. Returns a
  /// user-facing error message, or null on success.
  Future<String?> reconnect(
    XGuardInstance instance,
    Location location,
    RoutingMethod traffic,
  );
}

typedef ConfigFetcher =
    Future<ConfigPoll> Function(String proxyUrl, String token, String? revision);
typedef TokenReader = Future<String?> Function(XGuardInstance instance);

enum SyncResult { notModified, changed, failed }

class InstanceSyncReport {
  final SyncResult result;
  final PollFailure? failure;
  final UpdateInstanceResult? update;
  final TunnelAction tunnelAction;

  const InstanceSyncReport(
    this.result, {
    this.failure,
    this.update,
    this.tunnelAction = TunnelAction.none,
  });
}

class _InstanceSchedule {
  final SyncSchedule schedule = SyncSchedule();
  DateTime? nextDue;
  DateTime? lastPoll;
}

/// One worker that keeps every enrolled instance's configuration in sync: each
/// instance has its own schedule (server interval, backoff, jitter), polls run
/// one after another, and nothing runs while the app is in the background.
/// Revisions are kept in memory, so the first poll after a restart fetches the
/// full configuration once.
class ConfigSyncService {
  final AppDatabase db;
  final ConfigFetcher fetch;
  final TokenReader readToken;
  final ConfigSyncTunnels tunnels;
  final void Function(String message) notify;
  final Random _random;

  final Map<int, String> _revisions = {};
  final Map<int, _InstanceSchedule> _schedules = {};
  Timer? _timer;
  bool _active = false;
  Future<void>? _running;

  ConfigSyncService({
    required this.db,
    required this.fetch,
    required this.readToken,
    required this.tunnels,
    required this.notify,
    Random? random,
  }) : _random = random ?? Random();

  double _jitterUnit() => _random.nextDouble();

  @visibleForTesting
  String? revisionOf(int instanceId) => _revisions[instanceId];

  @visibleForTesting
  DateTime? nextDueOf(int instanceId) => _schedules[instanceId]?.nextDue;

  /// The app is in the foreground: the first poll runs 2-5 s from now.
  void start() {
    if (_active) return;
    _active = true;
    final first = clock.now().add(firstPollDelay(_jitterUnit()));
    for (final state in _schedules.values) {
      final due = state.nextDue;
      if (due == null || due.isBefore(first)) state.nextDue = first;
    }
    _arm(first.difference(clock.now()));
  }

  /// The app went to the background; timers stop.
  void pause() {
    _active = false;
    _timer?.cancel();
    _timer = null;
  }

  /// Back in the foreground: instances that are due, or were last polled more
  /// than one default interval ago (the network has likely changed), poll now.
  void resume() {
    if (_active) return;
    _active = true;
    final now = clock.now();
    for (final state in _schedules.values) {
      final last = state.lastPoll;
      if (last == null || now.difference(last) >= defaultPollInterval) {
        state.nextDue = now;
      }
    }
    _arm(Duration.zero);
  }

  void dispose() => pause();

  void _arm(Duration delay) {
    _timer?.cancel();
    if (!_active) return;
    _timer = Timer(delay.isNegative ? Duration.zero : delay, () {
      unawaited(runDue());
    });
  }

  /// Polls every instance that is due, one at a time, then waits for the next.
  Future<void> runDue() => _exclusive(() async {
    final instances = await db.managers.xguardInstances.get();
    final ids = instances.map((i) => i.id).toSet();
    _schedules.removeWhere((id, _) => !ids.contains(id));
    _revisions.removeWhere((id, _) => !ids.contains(id));
    final now = clock.now();
    for (final instance in instances) {
      final state = _schedules.putIfAbsent(instance.id, _InstanceSchedule.new);
      final due = state.nextDue;
      if (due != null && due.isAfter(now)) continue;
      await _syncAndSchedule(instance, state);
    }
  });

  /// A poll the user asked for (pull to refresh). Instances polled within the
  /// last [minTriggeredGap] are skipped. Returns the reports of the instances
  /// that were polled.
  Future<Map<int, InstanceSyncReport>> syncNow({int? instanceId}) async {
    final reports = <int, InstanceSyncReport>{};
    await _exclusive(() async {
      final instances = await db.managers.xguardInstances.get();
      final now = clock.now();
      for (final instance in instances) {
        if (instanceId != null && instance.id != instanceId) continue;
        final state = _schedules.putIfAbsent(
          instance.id,
          _InstanceSchedule.new,
        );
        final last = state.lastPoll;
        if (last != null && now.difference(last) < minTriggeredGap) continue;
        reports[instance.id] = await _syncAndSchedule(instance, state);
      }
    });
    return reports;
  }

  Future<void> _exclusive(Future<void> Function() work) async {
    while (_running != null) {
      await _running;
    }
    final completer = Completer<void>();
    _running = completer.future;
    try {
      await work();
    } catch (e, st) {
      talker.error('Configuration sync failed', e, st);
    } finally {
      _running = null;
      completer.complete();
      _armNext();
    }
  }

  void _armNext() {
    if (!_active) return;
    DateTime? earliest;
    for (final state in _schedules.values) {
      final due = state.nextDue;
      if (due != null && (earliest == null || due.isBefore(earliest))) {
        earliest = due;
      }
    }
    // An instance added since the last run is picked up by the default interval.
    final next = earliest ?? clock.now().add(defaultPollInterval);
    _arm(next.difference(clock.now()));
  }

  Future<InstanceSyncReport> _syncAndSchedule(
    XGuardInstance instance,
    _InstanceSchedule state,
  ) async {
    final (report, attempt) = await _sync(instance);
    state.lastPoll = clock.now();
    state.nextDue = clock.now().add(
      state.schedule.nextDelay(attempt, _jitterUnit()),
    );
    return report;
  }

  Future<(InstanceSyncReport, PollAttempt)> _sync(
    XGuardInstance instance,
  ) async {
    final token = await readToken(instance);
    if (token == null || token.isEmpty) {
      talker.warning(
        'Configuration sync skipped for ${instance.logName}: no polling token',
      );
      return (
        const InstanceSyncReport(
          SyncResult.failed,
          failure: PollFailure.missingToken,
        ),
        const PollRejected(),
      );
    }

    final ConfigPoll poll;
    try {
      poll = await fetch(
        instance.proxyUrl,
        token,
        _revisions[instance.id],
      );
    } on ConfigPollException catch (e) {
      talker.warning('Configuration sync of ${instance.logName} failed: $e');
      return (
        InstanceSyncReport(SyncResult.failed, failure: e.failure),
        PollAttempt.fromFailure(e.failure),
      );
    } catch (e) {
      talker.warning(
        'Configuration sync of ${instance.logName} failed: ${e.runtimeType}',
      );
      return (
        const InstanceSyncReport(
          SyncResult.failed,
          failure: PollFailure.network,
        ),
        const PollFailed(),
      );
    }

    switch (poll.outcome) {
      case PollNotModified():
        _storeRevision(instance.id, poll.revision);
        return (
          const InstanceSyncReport(SyncResult.notModified),
          PollSucceeded(poll.interval),
        );
      case PollChanged(:final config):
        final update = await updateInstance(
          db: db,
          instance: instance,
          configs: config.configs,
          info: config.instance,
          token: config.token,
        );
        if (update == null) {
          // Not applied: ask for the full configuration again next time.
          _revisions.remove(instance.id);
          return (
            const InstanceSyncReport(
              SyncResult.failed,
              failure: PollFailure.server,
            ),
            const PollFailed(),
          );
        }
        _storeRevision(instance.id, poll.revision);
        if (update.didChange) {
          talker.info(
            'Instance ${instance.logName} synced: '
            '${getInstanceUpdateMessage(instance.name, update)}',
          );
        }
        final action = await _applyToTunnel(instance, update);
        return (
          InstanceSyncReport(
            SyncResult.changed,
            update: update,
            tunnelAction: action,
          ),
          PollSucceeded(poll.interval),
        );
    }
  }

  void _storeRevision(int instanceId, String? revision) {
    if (revision == null) {
      _revisions.remove(instanceId);
    } else {
      _revisions[instanceId] = revision;
    }
  }

  Future<TunnelAction> applyExternalUpdate(
    XGuardInstance before,
    UpdateInstanceResult update,
  ) => _applyToTunnel(before, update);

  Future<TunnelAction> _applyToTunnel(
    XGuardInstance before,
    UpdateInstanceResult update,
  ) async {
    final active = tunnels.active;
    if (active == null || active.instanceId != before.id) {
      return TunnelAction.none;
    }
    try {
      final location = await db.managers.locations
          .filter((row) => row.id.equals(active.locationId))
          .getSingleOrNull();
      final action = planTunnelAction(
        activeLocationId: active.locationId,
        removedLocationIds: update.locationsRemoved.toSet(),
        tunnelChangedLocationIds: update.tunnelChanged,
        trafficPolicyChanged: update.trafficPolicyChanged,
        locationExists: location != null,
        locationNeedsMfa: location != null && shouldStartMfa(location),
      );
      switch (action) {
        case TunnelAction.none:
          break;
        case TunnelAction.disconnect:
          try {
            await tunnels.disconnect();
          } catch (e, st) {
            talker.error('Failed to disconnect removed tunnel', e, st);
          }
          notify(
            'A location of ${before.name} was removed by your administrator. '
            'Disconnected.',
          );
        case TunnelAction.reconnectByUser:
          final mustDisconnect =
              update.policyTightened.contains(active.locationId) ||
              update.trafficPolicyChanged;
          if (mustDisconnect) {
            try {
              await tunnels.disconnect();
            } catch (e, st) {
              talker.error(
                'Failed to disconnect tunnel after policy change',
                e,
                st,
              );
            }
            notify(
              'The security policy of ${location!.name} changed. Disconnected; '
              'reconnect to apply it.',
            );
          } else {
            notify(
              'The configuration of ${location!.name} changed. Reconnect to '
              'apply it.',
            );
          }
        case TunnelAction.reconnect:
          final instance = await db.managers.xguardInstances
              .filter((row) => row.id.equals(before.id))
              .getSingleOrNull();
          if (instance == null) break;
          final error = await tunnels.reconnect(
            instance,
            location!,
            active.traffic,
          );
          if (error != null) {
            try {
              await tunnels.disconnect();
            } catch (e, st) {
              talker.error(
                'Failed to disconnect tunnel after reconnect failure',
                e,
                st,
              );
            }
            notify('Reconnecting to ${location.name} failed: $error');
          } else {
            notify('${location.name} reconnected with its new configuration.');
          }
      }
      return action;
    } catch (e, st) {
      talker.error('Applying config sync changes to tunnel failed', e, st);
      return TunnelAction.none;
    }
  }
}
