import 'package:drift/drift.dart' as d;
import 'package:json_annotation/json_annotation.dart';

import '../db/database.dart';
import '../db/enums.dart';
import '../mfa/mfa_plan.dart';
import '../mfa/mfa_steps.dart';

part 'enrollment.g.dart';

@JsonSerializable()
class EnrollmentStartRequest {
  final String token;

  const EnrollmentStartRequest({required this.token});

  factory EnrollmentStartRequest.fromJson(Map<String, dynamic> json) =>
      _$EnrollmentStartRequestFromJson(json);

  Map<String, dynamic> toJson() => _$EnrollmentStartRequestToJson(this);
}

@JsonSerializable()
class EnrollmentSettings {
  final bool vpnSetupOptional;
  final bool onlyClientActivation;

  const EnrollmentSettings({
    required this.vpnSetupOptional,
    required this.onlyClientActivation,
  });

  factory EnrollmentSettings.fromJson(Map<String, dynamic> json) =>
      _$EnrollmentSettingsFromJson(json);

  Map<String, dynamic> toJson() => _$EnrollmentSettingsToJson(this);
}

@JsonSerializable()
class EnrollmentStartResponse {
  final AdminInfo admin;
  final UserInfo user;
  final EnrollmentInstanceInfo instance;
  final int deadlineTimestamp;
  final String finalPageContent;
  final EnrollmentSettings settings;

  factory EnrollmentStartResponse.fromJson(Map<String, dynamic> json) =>
      _$EnrollmentStartResponseFromJson(json);

  Map<String, dynamic> toJson() => _$EnrollmentStartResponseToJson(this);

  const EnrollmentStartResponse({
    required this.admin,
    required this.user,
    required this.instance,
    required this.deadlineTimestamp,
    required this.finalPageContent,
    required this.settings,
  });
}

@JsonSerializable()
class EnrollmentInstanceInfo {
  final String id;
  final String name;
  final String url;

  const EnrollmentInstanceInfo({
    required this.id,
    required this.name,
    required this.url,
  });

  factory EnrollmentInstanceInfo.fromJson(Map<String, dynamic> json) =>
      _$EnrollmentInstanceInfoFromJson(json);

  Map<String, dynamic> toJson() => _$EnrollmentInstanceInfoToJson(this);
}

@JsonSerializable()
class UserInfo {
  final String firstName;
  final String lastName;
  final String login;
  final String email;
  final bool isActive;
  final String? phoneNumber;
  final List<String> deviceNames;
  final bool enrolled;

  const UserInfo({
    required this.firstName,
    required this.lastName,
    required this.login,
    required this.email,
    required this.isActive,
    required this.deviceNames,
    required this.enrolled,
    this.phoneNumber,
  });

  factory UserInfo.fromJson(Map<String, dynamic> json) =>
      _$UserInfoFromJson(json);

  Map<String, dynamic> toJson() => _$UserInfoToJson(this);
}

@JsonSerializable()
class AdminInfo {
  final String name;
  final String email;
  final String? phoneNumber;

  const AdminInfo({required this.name, required this.email, this.phoneNumber});

  factory AdminInfo.fromJson(Map<String, dynamic> json) =>
      _$AdminInfoFromJson(json);

  Map<String, dynamic> toJson() => _$AdminInfoToJson(this);
}

@JsonSerializable()
class Device {
  final int id;
  final String name;
  final String pubkey;
  final int userId;
  final int createdAt;

  const Device({
    required this.id,
    required this.name,
    required this.pubkey,
    required this.userId,
    required this.createdAt,
  });

  factory Device.fromJson(Map<String, dynamic> json) => _$DeviceFromJson(json);

  Map<String, dynamic> toJson() => _$DeviceToJson(this);
}

/// Keeps an interface MTU in the WireGuard/daemon-accepted range (`576..=9200`),
/// dropping out-of-range values so the OS chooses a default instead.
int? sanitizeMtu(int? mtu) => (mtu != null && mtu >= 576 && mtu <= 9200) ? mtu : null;

@JsonSerializable()
class DeviceConfig {
  final int networkId;
  final String networkName;
  final String config;
  final String endpoint;
  final String assignedIp;
  final String pubkey;
  final String allowedIps;
  final String? dns;
  final bool mfaEnabled;
  final int keepaliveInterval;
  final LocationMfaMode? locationMfaMode;
  final bool? postureCheckRequired;
  @JsonKey(defaultValue: <MfaStep>[])
  final List<MfaStep> steps;

  /// [2.2] MTU resolved by the server (location value or the lowest group
  /// override). Null lets the platform pick.
  final int? mtu;

  /// Service locations (pre-logon, always-on) are run by the desktop client's
  /// background service. Core does not send them to mobile clients; any that
  /// arrive are ignored (see [isServiceLocation]).
  final int? serviceLocationMode;

  factory DeviceConfig.fromJson(Map<String, dynamic> json) =>
      _$DeviceConfigFromJson(json);

  Map<String, dynamic> toJson() => _$DeviceConfigToJson(this);

  const DeviceConfig({
    required this.networkId,
    required this.networkName,
    required this.config,
    required this.endpoint,
    required this.assignedIp,
    required this.pubkey,
    required this.allowedIps,
    this.dns,
    required this.mfaEnabled,
    required this.keepaliveInterval,
    this.locationMfaMode,
    this.postureCheckRequired,
    required this.steps,
    this.mtu,
    this.serviceLocationMode,
  });

  /// `ServiceLocationMode` 2 (pre-logon) and 3 (always-on).
  bool get isServiceLocation =>
      serviceLocationMode == 2 || serviceLocationMode == 3;

  int? get sanitizedMtu => sanitizeMtu(mtu);

  /// The settings a running tunnel is built from (and the MFA or posture
  /// requirements of connecting). A change here means a live tunnel is stale;
  /// a rename is not.
  bool tunnelSettingsMatch(Location other) =>
      pubkey == other.pubKey &&
      endpoint == other.endpoint &&
      assignedIp == other.address &&
      allowedIps == other.allowedIps &&
      dns == other.dns &&
      keepaliveInterval == other.keepAliveInterval &&
      sanitizedMtu == other.mtu &&
      postureCheckRequired == other.postureCheckRequired &&
      encodeMfaSteps(effectiveSteps) ==
          encodeMfaSteps(effectiveMfaSteps(other));

  /// Normalizes a pre-2.2 server's single-mode MFA into a one-step flow, so
  /// everything downstream only reads steps.
  List<MfaStep> get effectiveSteps =>
      steps.isNotEmpty ? steps : legacyMfaSteps(locationMfaMode, mfaEnabled);

  bool matchesLocation(Location other) {
    return networkId == other.networkId &&
        pubkey == other.pubKey &&
        networkName == other.name &&
        endpoint == other.endpoint &&
        assignedIp == other.address &&
        allowedIps == other.allowedIps &&
        dns == other.dns &&
        mfaEnabled == other.mfaEnabled &&
        keepaliveInterval == other.keepAliveInterval &&
        locationMfaMode == other.locationMfaMode &&
        postureCheckRequired == other.postureCheckRequired &&
        sanitizedMtu == other.mtu &&
        // Compared through the shim on both sides, so a legacy location does
        // not read as changed on the first poll after the column was added.
        encodeMfaSteps(effectiveSteps) ==
            encodeMfaSteps(effectiveMfaSteps(other));
  }

  LocationsCompanion toCompanion({
    int? id,
    MfaMethod? mfaMethod,
    RoutingMethod? trafficMethod,
    List<MfaMethod?>? mfaStepPlan,
    required int instanceId,
  }) {
    return LocationsCompanion(
      id: d.Value.absentIfNull(id),
      mfaMethod: d.Value.absentIfNull(mfaMethod),
      trafficMethod: d.Value.absentIfNull(trafficMethod),
      instance: d.Value(instanceId),
      dns: d.Value(dns),
      pubKey: d.Value(pubkey),
      networkId: d.Value(networkId),
      name: d.Value(networkName),
      mfaEnabled: d.Value(mfaEnabled),
      keepAliveInterval: d.Value(keepaliveInterval),
      endpoint: d.Value(endpoint),
      allowedIps: d.Value(allowedIps),
      address: d.Value(assignedIp),
      locationMfaMode: d.Value(locationMfaMode),
      postureCheckRequired: d.Value(postureCheckRequired),
      mfaSteps: d.Value(effectiveSteps),
      mfaStepPlan: d.Value.absentIfNull(mfaStepPlan),
      mtu: d.Value(sanitizedMtu),
    );
  }
}

@JsonSerializable()
class CreateDeviceRequest {
  final String name;
  final String pubkey;

  const CreateDeviceRequest({required this.name, required this.pubkey});

  factory CreateDeviceRequest.fromJson(Map<String, dynamic> json) =>
      _$CreateDeviceRequestFromJson(json);

  Map<String, dynamic> toJson() => _$CreateDeviceRequestToJson(this);
}

@JsonSerializable()
class CreateDeviceResponse {
  final Device device;
  final List<DeviceConfig> configs;
  final InstanceInfo instance;
  final String token;

  const CreateDeviceResponse({
    required this.device,
    required this.configs,
    required this.instance,
    required this.token,
  });

  factory CreateDeviceResponse.fromJson(Map<String, dynamic> json) =>
      _$CreateDeviceResponseFromJson(json);

  Map<String, dynamic> toJson() => _$CreateDeviceResponseToJson(this);
}

@JsonSerializable()
class InstanceInfo {
  final String id;
  final String name;
  final String url;
  final String proxyUrl;
  final String username;
  final bool enterpriseEnabled;
  final bool disableAllTraffic;
  final ClientTrafficPolicy? clientTrafficPolicy;
  final String? openidDisplayName;
  @JsonKey(unknownEnumValue: JsonKey.nullForUndefinedEnumValue)
  final OpenIdProvider? openidProviderKind;
  final Map<String, dynamic>? mfaUserState;

  /// [2.1] Hide, block and disconnect bare WireGuard tunnels. The mobile app
  /// only runs the instance's own locations, so there is nothing to block.
  final bool? disableTunnels;

  /// [2.2] An OpenID provider is configured and reachable through Edge.
  final bool? openidAvailable;

  const InstanceInfo({
    required this.id,
    required this.name,
    required this.url,
    required this.proxyUrl,
    required this.username,
    required this.enterpriseEnabled,
    @Deprecated('1.6') required this.disableAllTraffic,
    required this.clientTrafficPolicy,
    this.openidDisplayName,
    this.openidProviderKind,
    this.mfaUserState,
    this.disableTunnels,
    this.openidAvailable,
  });

  factory InstanceInfo.fromJson(Map<String, dynamic> json) =>
      _$InstanceInfoFromJson(json);

  Map<String, dynamic> toJson() => _$InstanceInfoToJson(this);

  bool matchesXGuardInstance(XGuardInstance other) {
    // `url` and `proxyUrl` are pinned to the values saved at enrollment so a
    // sync response cannot redirect the client to a different host.
    return id == other.uuid &&
        name == other.name &&
        username == other.username &&
        enterpriseEnabled == other.enterpriseEnabled &&
        getPolicy() == other.clientTrafficPolicy &&
        openidDisplayName == other.openidDisplayName &&
        openidProviderKind == other.openidProviderKind &&
        mfaContract == other.mfaContract;
  }

  XguardInstancesCompanion toCompanion({XGuardInstance? instance}) {
    return XguardInstancesCompanion(
      id: d.Value.absentIfNull(instance?.id),
      pubKey: d.Value.absentIfNull(instance?.pubKey),
      mfaKeysStored: d.Value.absentIfNull(instance?.mfaKeysStored),
      name: d.Value(name),
      url: d.Value(instance?.url ?? url),
      proxyUrl: d.Value(instance?.proxyUrl ?? proxyUrl),
      username: d.Value(username),
      enterpriseEnabled: d.Value(enterpriseEnabled),
      clientTrafficPolicy: d.Value(getPolicy()),
      uuid: d.Value(id),
      openidDisplayName: d.Value(openidDisplayName),
      openidProviderKind: d.Value(openidProviderKind),
      mfaContract: d.Value(mfaContract),
    );
  }

  /// Retrieves `ClientTrafficPolicy` while ensuring backwards compatibility
  ClientTrafficPolicy getPolicy() {
    return clientTrafficPolicy ??
        (disableAllTraffic
            ? ClientTrafficPolicy.disableAllTraffic
            : ClientTrafficPolicy.none);
  }

  MfaContract get mfaContract =>
      mfaUserState == null ? MfaContract.legacy : MfaContract.multiStep;
}

@JsonSerializable()
class AppInfoResponse {
  final String version;

  const AppInfoResponse({required this.version});

  factory AppInfoResponse.fromJson(Map<String, dynamic> json) =>
      _$AppInfoResponseFromJson(json);

  Map<String, dynamic> toJson() => _$AppInfoResponseToJson(this);
}

@JsonSerializable()
class WireguardEncodedKeyPair {
  final String pubKey;
  final String privKey;

  const WireguardEncodedKeyPair({required this.pubKey, required this.privKey});

  factory WireguardEncodedKeyPair.fromJson(Map<String, dynamic> json) =>
      _$WireguardEncodedKeyPairFromJson(json);

  Map<String, dynamic> toJson() => _$WireguardEncodedKeyPairToJson(this);
}

@JsonSerializable()
class RegisterMobileAuth {
  final String authPubKey;
  final String devicePubKey;

  const RegisterMobileAuth({
    required this.authPubKey,
    required this.devicePubKey,
  });

  factory RegisterMobileAuth.fromJson(Map<String, dynamic> json) =>
      _$RegisterMobileAuthFromJson(json);

  Map<String, dynamic> toJson() => _$RegisterMobileAuthToJson(this);
}
