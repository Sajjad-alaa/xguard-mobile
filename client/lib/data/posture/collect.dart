import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';
import 'package:mobile/data/client_identity.dart';
import 'package:mobile/data/posture/posture.dart';
import 'package:mobile/logging.dart';

/// Read-only platform probes. Android answers from the host activity
/// (`MainActivity.kt`, `KeyguardManager` and `DevicePolicyManager`), which need
/// no permission. iOS answers through `local_auth` (`LAContext`), which shows
/// no prompt for this query.
const _postureChannel = MethodChannel('local.xguard.mobile/posture');

/// Each probe is bounded so a stuck platform call cannot hold up a connect.
const _probeTimeout = Duration(seconds: 3);

Future<T?> _bounded<T>(Future<T?> Function() probe, String name) async {
  try {
    return await probe().timeout(_probeTimeout);
  } catch (e) {
    talker.warning('Posture probe $name failed: ${e.runtimeType}');
    return null;
  }
}

Future<Map<Object?, Object?>?> _androidFacts() =>
    _postureChannel.invokeMapMethod<Object?, Object?>('facts');

Future<bool?> _iosPasscodeSet() => LocalAuthentication().isDeviceSupported();

/// Collects the device's posture facts. Never throws: a fact that cannot be
/// read is left out.
Future<DevicePostureFacts> collectPostureFacts({
  ClientIdentitySource? identity,
  DateTime Function() now = DateTime.now,
}) async {
  final source = identity ?? clientIdentity;
  final resolved = await _bounded(source.get, 'identity');
  final facts = resolved?.facts;
  final os = switch (facts?.kind) {
    PlatformKind.android => PostureOs.android,
    PlatformKind.ios => PostureOs.ios,
    _ =>
      Platform.isAndroid
          ? PostureOs.android
          : Platform.isIOS
          ? PostureOs.ios
          : PostureOs.unspecified,
  };

  bool? deviceSecure;
  int? encryptionStatus;
  if (os == PostureOs.android) {
    final android = await _bounded(_androidFacts, 'android');
    final secure = android?['deviceSecure'];
    final status = android?['encryptionStatus'];
    deviceSecure = secure is bool ? secure : null;
    encryptionStatus = status is int ? status : null;
  } else if (os == PostureOs.ios) {
    deviceSecure = await _bounded(_iosPasscodeSet, 'passcode');
  }

  return buildPostureFacts(
    PostureProbes(
      os: os,
      osVersion: facts?.osVersion,
      clientVersion: resolved?.version,
      deviceSecure: deviceSecure,
      androidEncryptionStatus: encryptionStatus,
      androidSecurityPatch: facts?.androidSecurityPatch,
    ),
    now(),
  );
}
