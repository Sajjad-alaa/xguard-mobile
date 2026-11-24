import 'package:dio/dio.dart';
import 'package:mobile/data/posture/posture.dart';
import 'package:mobile/open/api.dart';

class ErrorHandler {
  static String getHumanReadableError(Object e) {
    if (e is PostureRejectedException) return e.userMessage;

    if (e is DioException) {
      switch (e.type) {
        case DioExceptionType.connectionTimeout:
        case DioExceptionType.sendTimeout:
        case DioExceptionType.receiveTimeout:
          return "Connection timed out. Please check your internet connection.";
        case DioExceptionType.connectionError:
          return _connectionErrorMessage;
        case DioExceptionType.badResponse:
          return _limitMessageFromResponse(e.response?.data) ??
              _statusMessage(e.response?.statusCode);
        case DioExceptionType.cancel:
          return "Request was cancelled.";
        default:
          // iOS error -1005: Network connection lost
          final errorString = e.error?.toString() ?? "";
          final messageString = e.message ?? "";
          if (errorString.contains("-1005") ||
              messageString.contains("-1005")) {
            return "Network connection lost. Please try again.";
          }

          return "An unexpected network error occurred.";
      }
    }

    if (e is MfaRequestException) {
      return switch (e.failure) {
        MfaRequestFailure.network => _connectionErrorMessage,
        MfaRequestFailure.policyDenied =>
          "This device does not meet the location's security requirements.",
        MfaRequestFailure.attemptLimit =>
          "Too many failed attempts. Start connecting again.",
        MfaRequestFailure.sessionExpired => _statusMessage(e.statusCode),
        MfaRequestFailure.staleAttempt => _statusMessage(e.statusCode),
        MfaRequestFailure.notReady =>
          "Verification can't start right now. Try again in a moment.",
        MfaRequestFailure.server => _statusMessage(e.statusCode),
      };
    }

    if (e is ProxyTlsException) {
      return switch (e.failure) {
        ProxyTlsFailure.untrusted =>
          "The server's certificate isn't trusted by this device. Contact your administrator.",
        ProxyTlsFailure.expired =>
          "The server's certificate is expired or not yet valid. Check your device's date or contact your administrator.",
        ProxyTlsFailure.hostnameMismatch =>
          "The server's certificate doesn't match its address. Check the URL or contact your administrator.",
        ProxyTlsFailure.other =>
          "Couldn't establish a secure connection to the server. Contact your administrator.",
      };
    }

    final s = e.toString();
    final lower = s.toLowerCase();
    if (lower.contains('device_limit_reached') ||
        lower.contains('device limit reached')) {
      return _deviceLimitMessage;
    }
    if (lower.contains('connection_limit_reached') ||
        lower.contains('connection limit reached') ||
        lower.contains('concurrent connection limit')) {
      return _connectionLimitMessage;
    }
    if (s.startsWith("Exception: ")) {
      return s.substring(11);
    }
    return s;
  }

  static const _deviceLimitMessage =
      "Maximum number of registered devices reached for your account. Remove an unused device or contact your administrator.";

  static const _connectionLimitMessage =
      "Maximum number of concurrent VPN connections reached for your account. Disconnect another device or contact your administrator.";

  static String? _limitMessageFromResponse(dynamic data) {
    if (data is Map) {
      final code = data['code']?.toString().toLowerCase() ?? '';
      final msg = data['msg']?.toString().toLowerCase() ?? '';
      if (code == 'device_limit_reached' ||
          msg.contains('device limit reached')) {
        return _deviceLimitMessage;
      }
      if (code == 'connection_limit_reached' ||
          msg.contains('connection limit reached') ||
          msg.contains('concurrent connection limit')) {
        return _connectionLimitMessage;
      }
    }
    return null;
  }

  static String getOpenIdMfaError(Object e) {
    if (e is PostureRejectedException) return e.userMessage;
    if (e is DioException && e.response == null) {
      return getHumanReadableError(e);
    }
    if (e is! MfaRequestException) {
      return "Authentication failed. Please try again.";
    }
    return switch (e.failure) {
      MfaRequestFailure.network => _connectionErrorMessage,
      MfaRequestFailure.policyDenied =>
        "This device does not meet the location's security requirements.",
      MfaRequestFailure.attemptLimit =>
        "Too many failed MFA attempts. Please try connecting again.",
      MfaRequestFailure.sessionExpired => "Session expired. Please try again.",
      MfaRequestFailure.staleAttempt =>
        "Authentication request could not be started. Please try again.",
      MfaRequestFailure.notReady =>
        "Verification can't start right now. Try again in a moment.",
      MfaRequestFailure.server => "Authentication failed. Please try again.",
    };
  }

  static const _connectionErrorMessage =
      "Unable to connect to the server. Please check your internet connection.";

  static String _statusMessage(int? statusCode) {
    if (statusCode == 401) {
      return "Unauthorized. Please check your credentials.";
    }
    if (statusCode == 403) {
      return "Access forbidden.";
    }
    if (statusCode == 404) {
      return "Service not found.";
    }
    if (statusCode != null && statusCode >= 500) {
      return "Server error. Please try again later.";
    }
    if (statusCode == null) {
      return "An unexpected network error occurred.";
    }
    return "Server returned an error: $statusCode";
  }
}
