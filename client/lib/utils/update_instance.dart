import 'package:collection/collection.dart';
import 'package:mobile/logging.dart';
import '../data/db/database.dart';
import '../data/mfa/mfa_plan.dart';
import '../data/proxy/enrollment.dart';

class UpdateInstanceResult {
  bool instanceChanged;
  int locationsAdded;
  List<int> locationsUpdated;
  List<int> locationsRemoved;

  /// Location row IDs whose tunnel settings (or MFA/posture requirements)
  /// changed, so a live tunnel built from the old ones is stale. A rename is
  /// not in here.
  Set<int> tunnelChanged;

  /// The instance's effective traffic policy changed.
  bool trafficPolicyChanged;

  UpdateInstanceResult({
    required this.instanceChanged,
    required this.locationsAdded,
    required this.locationsUpdated,
    required this.locationsRemoved,
    Set<int>? tunnelChanged,
    this.trafficPolicyChanged = false,
  }) : tunnelChanged = tunnelChanged ?? <int>{};

  bool get didChange {
    return locationsRemoved.isNotEmpty ||
        locationsUpdated.isNotEmpty ||
        instanceChanged ||
        locationsAdded > 0;
  }
}

Future<UpdateInstanceResult?> updateInstance({
  required AppDatabase db,
  required XGuardInstance instance,
  required List<DeviceConfig> configs,
  InstanceInfo? info,
  String? token,
}) async {
  talker.debug("${instance.logName} updated started");

  // A configuration for another instance must never overwrite this one.
  if (info != null && info.id != instance.uuid) {
    talker.error(
      "Instance ${instance.logName} not updated: the server sent the "
      "configuration of another instance",
    );
    return null;
  }
  // Service locations belong to the desktop client's background service.
  final usable = configs.where((config) => !config.isServiceLocation).toList();

  final result = UpdateInstanceResult(
    instanceChanged: false,
    locationsAdded: 0,
    locationsRemoved: [],
    locationsUpdated: [],
  );

  try {
    // Store rotated token first as it is the only copy
    if (token != null) {
      await instance.storeToken(token);
      talker.debug("${instance.logName} token updated");
    }

    final locations = await db.managers.locations
        .filter((row) => row.instance.id.equals(instance.id))
        .get();
    await db.transaction(() async {
      if (info != null && !info.matchesXGuardInstance(instance)) {
        final companion = info.toCompanion(instance: instance);
        await db.managers.xguardInstances
            .filter((row) => row.uuid.equals(instance.uuid))
            .update((_) => companion);
        result.instanceChanged = true;
        result.trafficPolicyChanged =
            info.getPolicy() != instance.clientTrafficPolicy;
      }

      // Remove deleted/revoked locations
      final existingConfigs = usable.map((c) => c.networkId).toSet();
      final List<int> toDelete = locations
          .where((location) => !existingConfigs.contains(location.networkId))
          .map((location) => location.id)
          .toList();
      if (toDelete.isNotEmpty) {
        await db.managers.locations
            .filter((row) => row.id.isIn(toDelete))
            .delete();
        result.locationsRemoved = toDelete;
        talker.debug("$toDelete Locations will be removed");
      }

      for (final config in usable) {
        final Location? location = locations.firstWhereOrNull(
          (l) => l.networkId == config.networkId,
        );
        if (location == null) {
          final companion = config.toCompanion(instanceId: instance.id);
          await db.managers.locations.create((_) => companion);
          talker.debug("Location ${config.networkName} will be added");
          result.locationsAdded++;
          continue;
        }
        if (!config.matchesLocation(location)) {
          final companion = config.toCompanion(
            instanceId: instance.id,
            id: location.id,
            trafficMethod: location.trafficMethod,
            mfaMethod: location.mfaMethod,
            mfaStepPlan: sanitizeMfaStepPlan(
              location.mfaStepPlan,
              config.effectiveSteps,
            ),
          );
          result.locationsUpdated.add(companion.id.value);
          if (!config.tunnelSettingsMatch(location)) {
            result.tunnelChanged.add(location.id);
          }
          await db.managers.locations
              .filter((loc) => loc.id.equals(location.id))
              .update((_) => companion);
          talker.debug("Location ${location.logName} will be changed");
        } else {
          talker.debug("Location ${location.logName} was unchanged");
        }
      }
    });
    talker.debug("Instance ${instance.logName} update transaction finished");
    return result;
  } catch (e) {
    talker.error("Instance ${instance.logName} update transaction failed!", e);
  }
  return null;
}

String getInstanceUpdateMessage(
  String instanceName,
  UpdateInstanceResult updateResult,
) {
  final buffer = StringBuffer();
  if (updateResult.instanceChanged) {
    buffer.write("Instance information updated. ");
  }
  if (updateResult.locationsRemoved.isNotEmpty) {
    buffer.write("${updateResult.locationsRemoved.length} locations removed. ");
  }
  if (updateResult.locationsAdded > 0) {
    buffer.write("${updateResult.locationsAdded} locations added. ");
  }
  if (updateResult.locationsUpdated.isNotEmpty) {
    buffer.write("${updateResult.locationsUpdated.length} locations updated.");
  }

  return buffer.toString().trim();
}
