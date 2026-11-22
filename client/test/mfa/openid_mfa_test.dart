import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:fake_async/fake_async.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile/data/mfa/mfa_flow.dart';
import 'package:mobile/data/mfa/openid_mfa.dart';
import 'package:mobile/open/api.dart';

void main() {
  group('buildOpenIdMfaUrl', () {
    test('builds HTTPS URL keeping path prefix and query parameters', () {
      expect(
        buildOpenIdMfaUrl(
          ' https://edge.example.com/vpn/?ignored=1#frag ',
          'sess-tok',
          'attempt-42',
        ).toString(),
        'https://edge.example.com/vpn/openid/mfa'
        '?token=sess-tok&step_attempt_id=attempt-42',
      );
    });

    test('omits step_attempt_id when null or empty', () {
      expect(
        buildOpenIdMfaUrl(
          'https://edge.example.com',
          'sess-tok',
          null,
        ).toString(),
        'https://edge.example.com/openid/mfa?token=sess-tok',
      );
      expect(
        buildOpenIdMfaUrl(
          'https://edge.example.com',
          'sess-tok',
          '',
        ).toString(),
        'https://edge.example.com/openid/mfa?token=sess-tok',
      );
    });

    test('permits plain HTTP only on loopback hosts', () {
      expect(
        buildOpenIdMfaUrl('http://localhost:8080', 't', null).toString(),
        'http://localhost:8080/openid/mfa?token=t',
      );
      expect(
        buildOpenIdMfaUrl('http://127.0.0.1:8080/p', 't', null).toString(),
        'http://127.0.0.1:8080/p/openid/mfa?token=t',
      );
      expect(
        buildOpenIdMfaUrl('http://[::1]:8080', 't', null).toString(),
        'http://[::1]:8080/openid/mfa?token=t',
      );
    });

    test('rejects insecure URLs, credentials in URL, and empty tokens', () {
      for (final badUrl in [
        'http://edge.example.com',
        'ftp://edge.example.com',
        'https://user:pass@edge.example.com',
        'https://',
        'not a :// url',
      ]) {
        expect(
          () => buildOpenIdMfaUrl(badUrl, 'tok', null),
          throwsA(isA<OpenIdUrlException>()),
          reason: badUrl,
        );
      }

      expect(
        () => buildOpenIdMfaUrl('https://edge.example.com', '', 'attempt'),
        throwsA(isA<OpenIdUrlException>()),
      );
    });
  });

  group('OpenIdMfaPoller', () {
    test('polls until leaving MfaStepAwaiting and returns outcome', () {
      fakeAsync((async) {
        var calls = 0;
        final poller = OpenIdMfaPoller(
          interval: const Duration(seconds: 5),
          timeout: const Duration(minutes: 5),
          poll: () async {
            calls++;
            return calls < 3
                ? const MfaStepAwaiting()
                : const MfaStepCompleted();
          },
        );

        OpenIdPollOutcome? outcome;
        poller.run().then((value) => outcome = value);
        async.flushMicrotasks();
        expect(calls, 1);
        expect(outcome, isNull);

        async.elapse(const Duration(seconds: 5));
        expect(calls, 2);
        expect(outcome, isNull);

        async.elapse(const Duration(seconds: 5));
        expect(calls, 3);
        expect(
          outcome,
          isA<OpenIdPollFinished>().having(
            (o) => o.progress,
            'progress',
            isA<MfaStepCompleted>(),
          ),
        );
        expect(poller.isRunning, isFalse);
      });
    });

    test('tolerates up to maxNetworkErrors and resets after success', () {
      fakeAsync((async) {
        var calls = 0;
        final poller = OpenIdMfaPoller(
          interval: const Duration(seconds: 5),
          timeout: const Duration(minutes: 5),
          maxNetworkErrors: 3,
          poll: () async {
            calls++;
            if (calls <= 3) {
              throw const MfaRequestException(
                'poll',
                failure: MfaRequestFailure.network,
              );
            }
            if (calls == 4) return const MfaStepAwaiting();
            if (calls <= 7) throw const SocketException('lost');
            return const MfaStepAdvanced();
          },
        );

        OpenIdPollOutcome? outcome;
        poller.run().then((value) => outcome = value);
        async.elapse(const Duration(seconds: 35));
        expect(calls, 8);
        expect(
          outcome,
          isA<OpenIdPollFinished>().having(
            (o) => o.progress,
            'progress',
            isA<MfaStepAdvanced>(),
          ),
        );
      });
    });

    test('fails after exceeding maxNetworkErrors or on non-network error', () {
      fakeAsync((async) {
        var calls = 0;
        final poller = OpenIdMfaPoller(
          interval: const Duration(seconds: 5),
          maxNetworkErrors: 2,
          poll: () async {
            calls++;
            throw TimeoutException('slow');
          },
        );

        OpenIdPollOutcome? outcome;
        poller.run().then((value) => outcome = value);
        async.elapse(const Duration(seconds: 15));
        expect(calls, 3);
        expect(outcome, isA<OpenIdPollFailed>());
      });

      fakeAsync((async) {
        var calls = 0;
        final poller = OpenIdMfaPoller(
          poll: () async {
            calls++;
            throw const MfaRequestException(
              'poll',
              statusCode: 400,
              failure: MfaRequestFailure.staleAttempt,
            );
          },
        );

        OpenIdPollOutcome? outcome;
        poller.run().then((value) => outcome = value);
        async.flushMicrotasks();
        expect(calls, 1);
        expect(
          outcome,
          isA<OpenIdPollFailed>().having(
            (o) => (o.error as MfaRequestException).failure,
            'failure',
            MfaRequestFailure.staleAttempt,
          ),
        );
      });

      fakeAsync((async) {
        final poller = OpenIdMfaPoller(
          poll: () async => throw DioException(
            requestOptions: RequestOptions(path: '/'),
            response: Response(
              requestOptions: RequestOptions(path: '/'),
              statusCode: 500,
            ),
          ),
        );

        OpenIdPollOutcome? outcome;
        poller.run().then((value) => outcome = value);
        async.flushMicrotasks();
        expect(outcome, isA<OpenIdPollFailed>());
      });
    });

    test('pollNow wakes early and cancel stops sleeping poller', () {
      fakeAsync((async) {
        var calls = 0;
        final poller = OpenIdMfaPoller(
          interval: const Duration(seconds: 5),
          poll: () async {
            calls++;
            return const MfaStepAwaiting();
          },
        );

        OpenIdPollOutcome? outcome;
        poller.run().then((value) => outcome = value);
        async.flushMicrotasks();
        expect(calls, 1);

        async.elapse(const Duration(seconds: 1));
        poller.pollNow();
        async.flushMicrotasks();
        expect(calls, 2);

        poller.cancel();
        async.flushMicrotasks();
        expect(outcome, isA<OpenIdPollCancelled>());
        expect(poller.isRunning, isFalse);
      });
    });

    test('times out after deadline and rejects concurrent run()', () {
      fakeAsync((async) {
        final poller = OpenIdMfaPoller(
          interval: const Duration(seconds: 5),
          timeout: const Duration(seconds: 12),
          poll: () async => const MfaStepAwaiting(),
        );

        OpenIdPollOutcome? outcome;
        poller.run().then((value) => outcome = value);
        async.flushMicrotasks();
        expect(() => poller.run(), throwsStateError);

        async.elapse(const Duration(seconds: 12));
        expect(outcome, isA<OpenIdPollTimedOut>());
      });
    });
  });
}
