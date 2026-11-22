import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mobile/data/config_sync/config_sync.dart';
import 'package:mobile/data/config_sync/sync_service.dart';
import 'package:mobile/data/db/database.dart';
import 'package:mobile/data/db/enums.dart';
import 'package:mobile/data/plugin/plugin.dart';
import 'package:mobile/open/api.dart';
import 'package:mobile/open/riverpod/plugin/plugin.dart';
import 'package:mobile/open/screens/instance/services/tunnel_service.dart';
import 'package:mobile/open/widgets/toaster/toast_manager.dart';
import 'package:mobile/plugin.dart';
import 'package:wireguard_plugin/wireguard_plugin.dart';

class _PluginTunnels implements ConfigSyncTunnels {
  final Ref ref;

  _PluginTunnels(this.ref);

  WireguardPlugin get _plugin => ref.read(wireguardPluginProvider);

  @override
  PluginTunnelEventData? get active => ref.read(pluginActiveTunnelStateProvider);

  @override
  Future<void> disconnect() => _plugin.closeTunnel();

  @override
  Future<String?> reconnect(
    XGuardInstance instance,
    Location location,
    RoutingMethod traffic,
  ) async {
    final result = await TunnelService.reconnectUnattended(
      instance: instance,
      location: location,
      wireguardPlugin: _plugin,
      trafficMethod: traffic,
    );
    return result.status == ConnectStatus.connected
        ? null
        : (result.message ?? 'unknown error');
  }
}

final configSyncServiceProvider = Provider<ConfigSyncService>((ref) {
  final service = ConfigSyncService(
    db: ref.read(databaseProvider),
    fetch: (proxyUrl, token, revision) =>
        proxyApi.fetchConfig(proxyUrl, token, revision: revision),
    readToken: (instance) => instance.pollingToken(),
    tunnels: _PluginTunnels(ref),
    notify: (message) =>
        ref.read(toastManagerProvider.notifier).show(message: message),
  );
  ref.onDispose(service.dispose);
  return service;
});

/// Runs configuration sync while the app is in the foreground.
class ConfigSyncController extends HookConsumerWidget {
  final Widget child;

  const ConfigSyncController({super.key, required this.child});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final service = ref.watch(configSyncServiceProvider);
    useEffect(() {
      service.start();
      return null;
    }, [service]);
    useOnAppLifecycleStateChange((_, state) {
      switch (state) {
        case AppLifecycleState.resumed:
          service.resume();
        case AppLifecycleState.paused:
        case AppLifecycleState.detached:
          service.pause();
        default:
          break;
      }
    });
    return child;
  }
}

/// A short summary of a manual sync for a toast.
String manualSyncMessage(Map<int, InstanceSyncReport> reports) {
  if (reports.isEmpty) return 'Already up to date.';
  final failed = reports.values
      .where((report) => report.result == SyncResult.failed)
      .toList();
  final changed = reports.values
      .where((report) => report.result == SyncResult.changed)
      .length;
  if (failed.isNotEmpty) {
    final reason = switch (failed.first.failure) {
      PollFailure.unauthorized =>
        'this device is no longer known to the server; add the instance again',
      PollFailure.forbidden => 'the server refused this device',
      PollFailure.rateLimited => 'try again in a moment',
      PollFailure.unsupported => 'the server does not support configuration sync',
      PollFailure.missingToken => 'the device token is missing',
      PollFailure.invalidUrl => 'the instance URL is not HTTPS',
      _ => 'the server could not be reached',
    };
    return reports.length == 1
        ? 'Sync failed: $reason.'
        : '${failed.length} of ${reports.length} instances failed to sync: '
              '$reason.';
  }
  if (changed == 0) return 'Already up to date.';
  return changed == 1
      ? 'Configuration updated.'
      : 'Configuration of $changed instances updated.';
}
