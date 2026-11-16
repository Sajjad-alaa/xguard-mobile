import 'dart:convert';

import 'package:drift/drift.dart' as drift;
import 'package:material_ui/material_ui.dart';
import 'package:mobile/data/db/database.dart';
import 'package:mobile/data/mfa/mfa_flow.dart';
import 'package:mobile/data/mfa/mfa_transport.dart';
import 'package:mobile/data/mfa/mfa_plan.dart';
import 'package:mobile/data/plugin/plugin.dart';
import 'package:mobile/logging.dart';
import 'package:mobile/open/api.dart';
import 'package:mobile/open/riverpod/biometrics_state.dart';
import 'package:mobile/open/screens/mfa/mfa_step_flow.dart';
import 'package:mobile/utils/instance_secrets.dart';
import 'package:mobile/utils/update_instance.dart';

import '../../../../data/db/enums.dart';
import '../../../../utils/notifications.dart';

/// How a connect attempt ended. Reporting it - a toast, a snackbar, nothing at
/// all - is the caller's business, the service only states what happened.
enum ConnectStatus { connected, cancelled, failed }

class ConnectResult {
  final ConnectStatus status;

  /// Safe, user facing text. Set only when [status] is [ConnectStatus.failed].
  final String? message;

  /// Detail for the log, never displayed.
  final String? logMessage;
  final Object? error;

  const ConnectResult.connected()
    : status = ConnectStatus.connected,
      message = null,
      logMessage = null,
      error = null;

  const ConnectResult.cancelled()
    : status = ConnectStatus.cancelled,
      message = null,
      logMessage = null,
      error = null;

  const ConnectResult.failed({
    required this.message,
    this.logMessage,
    this.error,
  }) : status = ConnectStatus.failed;
}

/// Handles MFA flows and tunnel connection
class TunnelService {
  /// Main service method - handles MFA, interface configuration and connection.
  ///
  /// The caller collects the user's traffic and MFA choices up front (the
  /// connect bottom sheet does), so this method never puts UI of its own in
  /// front of the user except the MFA step screens.
  static Future<ConnectResult> connect({
    required BuildContext context,
    required XGuardInstance instance,
    required Location location,
    required dynamic wireguardPlugin,
    required BiometricsState biometricsStatus,
    required AppDatabase db,
    required RoutingMethod trafficMethod,

    /// Overrides the saved default for the steps it covers, positionally.
    List<MfaMethod?> mfaPlan = const [],
  }) async {
    final navigator = Navigator.of(context);

    final privateKey = await instance.wireguardPrivateKey();
    if (privateKey == null) {
      reportMissingSecret(instance.logName, "WireGuard private key");
      return const ConnectResult.failed(message: missingSecretsMessage);
    }
    PluginConnectPayload payload = _makePayload(
      instance,
      location,
      trafficMethod,
      privateKey,
    );
    MfaMethod? authorizedWith;

    if (shouldStartMfa(location)) {
      final capabilities = MfaCapabilities(
        biometricAvailable:
            instance.mfaKeysStored && biometricsStatus.canOpenStorage,
        contract: instance.mfaContract,
      );
      final resolved = resolveMfaStepPlan(
        location,
        oneOff: mfaPlan,
        capabilities: capabilities,
      );
      if (resolved.isEmpty || resolved.contains(null)) {
        return const ConnectResult.failed(
          message: "This location cannot be verified from the mobile app.",
          logMessage: "Connect attempted on a location with an unpassable step",
        );
      }
      final plan = resolved.cast<MfaMethod>();
      talker.debug(
        "Starting ${plan.length}-step MFA for networkId ${payload.networkId}: "
        "${plan.map((m) => m.toReadableString()).join(', ')}",
      );

      await requestNotificationPermissions();
      final flow = MfaStepFlow(
        navigator: navigator,
        controller: MfaFlowController(
          transport: mfaTransportForContract(
            instance.mfaContract,
            Uri.parse(instance.proxyUrl),
          ),
          plan: plan,
          devicePubkey: payload.devicePublicKey,
          networkId: payload.networkId,
          refreshPlan: instance.mfaContract == MfaContract.multiStep
              ? () async {
                  final retry = await _refreshMfaPlan(
                    db: db,
                    instance: instance,
                    location: location,
                    oneOff: mfaPlan,
                    capabilities: capabilities,
                  );
                  if (retry == null) return null;
                  final refreshed = _makePayload(
                    retry.instance,
                    retry.location,
                    trafficMethod,
                    privateKey,
                  );
                  if (!canReuseMfaAttempt(payload, refreshed)) {
                    talker.warning(
                      "Not retrying MFA for networkId ${payload.networkId}: "
                      "the refresh changed what the started attempt was bound to",
                    );
                    return null;
                  }
                  payload = refreshed;
                  return retry.plan;
                }
              : null,
        ),
        proxyUrl: instance.proxyUrl,
        instanceUrl: instance.url,
        secureStorageKey: instance.secureStorageKey,
        openidDisplayName: instance.openidDisplayName,
        openidProvider: instance.openidProviderKind,
      );

      switch (await flow.run()) {
        case MfaFlowCancelled():
          return const ConnectResult.cancelled();
        case MfaFlowFailed(:final message, :final logMessage, :final error):
          return ConnectResult.failed(
            message: message,
            logMessage: logMessage,
            error: error,
          );
        case MfaFlowConnected():
          payload.presharedKey = flow.controller.takePresharedKey();
      }
      // Only a single-step flow has one method to show. A multi-step one shows
      // its step count instead.
      final completedPlan = flow.controller.plan;
      authorizedWith = completedPlan.length == 1 ? completedPlan.single : null;
    } else if (payload.postureCheckRequired) {
      // Device posture checks were part of the Defguard enterprise edition and are not
      // supported by XGuard; current servers never require them.
      return const ConnectResult.failed(
        message:
            'This location requires device posture checks, which XGuard does not support.',
      );
    }

    await wireguardPlugin.startTunnel(jsonEncode(payload.toJson()));

    // The original instance, not a refreshed one: its policy decided whether
    // the connect sheet let the user pick [trafficMethod].
    await _rememberPreferences(
      db,
      instance,
      location,
      trafficMethod: trafficMethod,
      // null unless an MFA step actually ran
      mfaMethod: authorizedWith,
    );

    return const ConnectResult.connected();
  }

  /// Stores the connection preferences on the location row so the next connect
  /// can pre-select them, and so the UI can show what authorized the tunnel.
  ///
  /// Runs only after the tunnel actually started, so a cancelled or failed
  /// connect never overwrites a working preference. Fields left absent keep
  /// their stored value - passing `Value(null)` would clear them instead.
  static Future<void> _rememberPreferences(
    AppDatabase db,
    XGuardInstance instance,
    Location location, {
    required RoutingMethod trafficMethod,
    MfaMethod? mfaMethod,
  }) async {
    // Under a forced policy the routing was not the user's choice, so there is
    // nothing worth remembering.
    final traffic = instance.clientTrafficPolicy == ClientTrafficPolicy.none
        ? drift.Value(trafficMethod)
        : const drift.Value<RoutingMethod?>.absent();
    final mfa = mfaMethod != null
        ? drift.Value(mfaMethod)
        : const drift.Value<MfaMethod?>.absent();
    // Set only for a single-step flow, where the sheet's picker is also how the
    // step's default changes. A multi-step plan is owned by the MFA settings
    // screen and left alone here.
    final plan = mfaMethod != null
        ? drift.Value<List<MfaMethod?>>([mfaMethod])
        : const drift.Value<List<MfaMethod?>>.absent();

    if (!traffic.present && !mfa.present) {
      return;
    }

    try {
      await (db.update(
        db.locations,
      )..where((t) => t.id.equals(location.id))).write(
        LocationsCompanion(
          trafficMethod: traffic,
          mfaMethod: mfa,
          mfaStepPlan: plan,
        ),
      );
    } catch (e) {
      talker.error(
        "Failed to remember connection preferences for location ${location.id}",
        e,
      );
    }
  }

  /// The started attempt is bound to the device key, network and posture data,
  /// so a retry may reuse it only when the refresh left those unchanged.
  @visibleForTesting
  static bool canReuseMfaAttempt(
    PluginConnectPayload attempt,
    PluginConnectPayload refreshed,
  ) =>
      attempt.devicePublicKey == refreshed.devicePublicKey &&
      attempt.networkId == refreshed.networkId &&
      attempt.postureCheckRequired == refreshed.postureCheckRequired;

  static Future<
    ({List<MfaMethod> plan, XGuardInstance instance, Location location})?
  >
  _refreshMfaPlan({
    required AppDatabase db,
    required XGuardInstance instance,
    required Location location,
    required List<MfaMethod?> oneOff,
    required MfaCapabilities capabilities,
  }) async {
    final token = await instance.pollingToken();
    if (token == null) return null;

    final (config, _, _) = await proxyApi.pollConfiguration(
      instance.proxyUrl,
      token,
    );
    if (config == null) return null;

    final update = await updateInstance(
      db: db,
      instance: instance,
      configs: config.configs,
      info: config.instance,
      token: config.token,
    );
    if (update == null) return null;

    final refreshedInstance = await db.managers.xguardInstances
        .filter((row) => row.id.equals(instance.id))
        .getSingleOrNull();
    if (refreshedInstance == null) return null;

    final refreshedLocation = await db.managers.locations
        .filter((row) => row.id.equals(location.id))
        .getSingleOrNull();
    if (refreshedLocation == null) return null;

    final plan = resolveMfaRetryPlan(
      refreshedLocation,
      attempt: capabilities,
      refreshedContract: refreshedInstance.mfaContract,
      oneOff: oneOff,
    );
    if (plan == null) return null;
    return (
      plan: plan,
      instance: refreshedInstance,
      location: refreshedLocation,
    );
  }

  /// Whether the location has an MFA flow to satisfy. Legacy single-mode
  /// locations are normalized into a one-step flow by `effectiveMfaSteps`.
  static bool checkMfaEnabled(Location location) => shouldStartMfa(location);

  static PluginConnectPayload _makePayload(
    XGuardInstance instance,
    Location location,
    RoutingMethod trafficMethod,
    String privateKey,
  ) {
    // The administrator's instance policy outranks the caller's choice.
    final selectedTrafficMethod = switch (instance.clientTrafficPolicy) {
      ClientTrafficPolicy.disableAllTraffic => RoutingMethod.predefined,
      ClientTrafficPolicy.forceAllTraffic => RoutingMethod.all,
      ClientTrafficPolicy.none => trafficMethod,
    };
    return PluginConnectPayload(
      publicKey: location.pubKey,
      devicePublicKey: instance.pubKey,
      privateKey: privateKey,
      address: location.address,
      dns: location.dns,
      endpoint: location.endpoint,
      allowedIps: location.allowedIps,
      keepalive: location.keepAliveInterval,
      locationName: location.name,
      locationId: location.id,
      networkId: location.networkId,
      instanceId: instance.id,
      traffic: selectedTrafficMethod,
      postureCheckRequired: location.postureCheckRequired == true,
    );
  }
}
