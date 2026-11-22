import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mobile/data/db/enums.dart';
import 'package:mobile/data/mfa/openid_mfa.dart';
import 'package:mobile/data/posture/posture.dart';
import 'package:mobile/logging.dart';
import 'package:mobile/open/api.dart';
import 'package:mobile/open/screens/mfa/mfa_step_chrome.dart';
import 'package:mobile/open/widgets/dg_app_bar.dart';
import 'package:mobile/open/widgets/dg_button.dart';
import 'package:mobile/open/widgets/dg_icon_button.dart';
import 'package:mobile/open/widgets/dg_mfa_step_label.dart';
import 'package:mobile/open/widgets/dg_openid_mfa_layout.dart';
import 'package:mobile/open/widgets/icons/dg_icon.dart';
import 'package:mobile/open/widgets/rive_asset_animation.dart';
import 'package:mobile/theme/color.dart';
import 'package:mobile/theme/spacing.dart';
import 'package:mobile/theme/text.dart';
import 'package:mobile/utils/error_handler.dart';
import 'package:url_launcher/url_launcher.dart';

/// Opens [url] in a custom tab (Android) or Safari view (iOS), falling back to
/// the default browser. The sign-in, the provider and Edge's callback all run
/// in that one browser, which holds the binding cookie Edge set.
typedef OpenIdBrowserLauncher = Future<bool> Function(Uri url);

Future<bool> launchOpenIdBrowser(Uri url) async {
  try {
    if (await supportsLaunchMode(LaunchMode.inAppBrowserView)) {
      if (await launchUrl(url, mode: LaunchMode.inAppBrowserView)) {
        return true;
      }
      await _closeOpenIdBrowser();
    }
  } catch (e) {
    talker.warning('In-app browser unavailable: ${e.runtimeType}');
    await _closeOpenIdBrowser();
  }
  return launchUrl(url, mode: LaunchMode.externalApplication);
}

Future<void> _closeOpenIdBrowser() async {
  try {
    if (await supportsCloseForLaunchMode(LaunchMode.inAppBrowserView)) {
      await closeInAppWebView();
    }
  } catch (_) {
    // Nothing to close, or the platform cannot.
  }
}

enum _Phase { intro, waiting, retry }

/// OpenID VPN MFA: the user signs in at the identity provider through Edge's
/// OpenID MFA page in the browser, and the app polls Edge until Core reports
/// the step done. The browser sign-in is bound to this MFA attempt (session
/// token and attempt ID), so it cannot finish another one.
class MfaOpenIdScreen extends HookConsumerWidget {
  final MfaStepHost host;
  final String proxyUrl;
  final String? openidDisplayName;
  final OpenIdProvider openidProvider;
  final OpenIdBrowserLauncher launcher;

  const MfaOpenIdScreen({
    super.key,
    required this.host,
    required this.proxyUrl,
    required this.openidProvider,
    this.openidDisplayName,
    this.launcher = launchOpenIdBrowser,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final phase = useState(_Phase.intro);
    final error = useState<String?>(null);
    final poller = useRef<OpenIdMfaPoller?>(null);
    final url = useRef<Uri?>(null);
    final launching = useRef(false);
    final mounted = useRef(true);

    useEffect(() {
      return () {
        mounted.value = false;
        poller.value?.cancel();
      };
    }, const []);
    useOnAppLifecycleStateChange((_, state) {
      if (state == AppLifecycleState.resumed) poller.value?.pollNow();
    });

    Future<void> waitForSignIn() async {
      final current = OpenIdMfaPoller(
        poll: () => host.controller.submit(),
      );
      poller.value = current;
      phase.value = _Phase.waiting;
      error.value = null;
      final outcome = await current.run();
      if (!mounted.value || !identical(poller.value, current)) return;
      poller.value = null;
      switch (outcome) {
        case OpenIdPollFinished(:final progress):
          unawaited(_closeOpenIdBrowser());
          host.reportProgress(progress);
        case OpenIdPollCancelled():
          break;
        case OpenIdPollTimedOut():
          unawaited(_closeOpenIdBrowser());
          host.reportFailure(
            message: 'The sign-in took too long. Start connecting again.',
            logMessage: 'OpenID MFA timed out',
          );
        case OpenIdPollFailed(error: final failure):
          unawaited(_closeOpenIdBrowser());
          if (reportIfPostureRejected(host, failure) ||
              reportIfAttemptLimit(host, failure)) {
            return;
          }
          if (failure is MfaRequestException &&
              (failure.failure == MfaRequestFailure.sessionExpired ||
                  failure.failure == MfaRequestFailure.staleAttempt)) {
            host.reportFailure(
              message:
                  'The sign-in did not complete for this connection. If you '
                  'signed in with another account, use the one linked to '
                  'XGuard. Start connecting again.',
              logMessage: 'OpenID MFA session ended while waiting',
              error: failure,
            );
            return;
          }
          final logError = failure is PostureRejectedException ? null : failure;
          talker.error('OpenID MFA polling failed', logError);
          error.value = ErrorHandler.getOpenIdMfaError(failure);
          phase.value = _Phase.retry;
      }
    }

    Future<void> openBrowser() async {
      if (launching.value) return;
      launching.value = true;
      try {
        final token = host.controller.token;
        final Uri target;
        try {
          target =
              url.value ??
              buildOpenIdMfaUrl(
                proxyUrl,
                token ?? '',
                host.controller.stepAttemptId,
              );
        } on OpenIdUrlException catch (e) {
          host.reportFailure(
            message: 'This instance cannot use OpenID verification.',
            logMessage: 'OpenID MFA URL refused: ${e.message}',
            error: e,
          );
          return;
        }
        url.value = target;
        final bool opened;
        try {
          opened = await launcher(target);
        } catch (e) {
          if (!mounted.value) return;
          error.value = 'Could not open the browser.';
          final detail = e is PlatformException ? ' (${e.code})' : '';
          talker.error(
            'Failed to open the OpenID MFA page: ${e.runtimeType}$detail',
          );
          return;
        }
        if (!mounted.value) return;
        if (!opened) {
          error.value = 'Could not open the browser.';
          return;
        }
        if (poller.value == null) unawaited(waitForSignIn());
      } finally {
        launching.value = false;
      }
    }

    if (phase.value == _Phase.intro) {
      return MfaStepScope(
        host: host,
        child: DgOpenIdMfaLayout(
          openidDisplayName: openidDisplayName,
          openidProvider: openidProvider,
          stepLabel: host.controller.stepLabel,
          errorMessage: error.value,
          onContinue: openBrowser,
          onBack: host.abort,
        ),
      );
    }

    final waiting = phase.value == _Phase.waiting;
    return MfaStepScope(
      host: host,
      child: Container(
        decoration: const BoxDecoration(gradient: DgColor.gradientPrimary),
        child: Scaffold(
          backgroundColor: Colors.transparent,
          appBar: DgAppBar(
            context: context,
            showLogo: false,
            actionLeft: DgIconButton(
              icon: 'arrow_small',
              direction: DgIconDirection.left,
              onTap: host.abort,
            ),
          ),
          body: SafeArea(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(20, 4, 20, 20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  DgMfaStepLabel(host.controller.stepLabel),
                  Text(
                    waiting
                        ? 'Finish signing in'
                        : 'Could not check the sign-in',
                    style: DgText.h4.copyWith(color: DgColor.fgWhite100),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    waiting
                        ? 'Sign in with ${MfaMethod.openid.toUiString(openidDisplayName: openidDisplayName)} '
                              'in the browser. XGuard connects as soon as the '
                              'sign-in is done.'
                        : error.value ?? 'Try again.',
                    key: const Key('mfa_openid_status'),
                    style: DgText.bodySm400.copyWith(color: DgColor.fgWhite60),
                  ),
                  const Expanded(
                    child: RiveAssetAnimation('assets/next/rive/open_id.riv'),
                  ),
                  if (waiting && error.value != null) ...[
                    Text(
                      error.value!,
                      style: DgText.bodySm400.copyWith(
                        color: DgColor.fgWhite80,
                      ),
                    ),
                    const SizedBox(height: DgSpacing.md),
                  ],
                  DgButton(
                    identifier: 'mfa_openid_reopen',
                    text: waiting ? 'Open the browser again' : 'Try again',
                    style: DgButtonStyle.primary,
                    size: DgButtonSize.big,
                    width: double.infinity,
                    onTap: waiting ? openBrowser : waitForSignIn,
                  ),
                  const SizedBox(height: DgSpacing.md),
                  DgButton(
                    identifier: 'mfa_openid_cancel',
                    text: 'Cancel',
                    style: DgButtonStyle.secondary,
                    size: DgButtonSize.big,
                    width: double.infinity,
                    onTap: host.abort,
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
