import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/utils/error_handler.dart';

void main() {
  group('ErrorHandler limit messages', () {
    test('maps device_limit_reached API response to user-friendly message', () {
      final err = DioException(
        requestOptions: RequestOptions(path: '/api/v1/device'),
        type: DioExceptionType.badResponse,
        response: Response(
          requestOptions: RequestOptions(path: '/api/v1/device'),
          statusCode: 403,
          data: {
            'code': 'device_limit_reached',
            'msg': 'Device limit reached for this user',
          },
        ),
      );
      expect(
        ErrorHandler.getHumanReadableError(err),
        contains('Maximum number of registered devices reached'),
      );
    });

    test('maps connection_limit_reached API response to user-friendly message', () {
      final err = DioException(
        requestOptions: RequestOptions(path: '/api/v1/mfa-flow/finish'),
        type: DioExceptionType.badResponse,
        response: Response(
          requestOptions: RequestOptions(path: '/api/v1/mfa-flow/finish'),
          statusCode: 409,
          data: {
            'code': 'connection_limit_reached',
            'msg': 'Concurrent connection limit reached',
          },
        ),
      );
      expect(
        ErrorHandler.getHumanReadableError(err),
        contains('Maximum number of concurrent VPN connections reached'),
      );
    });
  });
}
