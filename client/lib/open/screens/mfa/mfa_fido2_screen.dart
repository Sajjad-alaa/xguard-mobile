import 'dart:async';

import 'package:fido2_plugin/fido2_plugin.dart';
import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mobile/data/fido2/ceremony.dart';
import 'package:mobile/data/mfa/mfa_flow.dart';
import 'package:mobile/data/proxy/mfa.dart';
import 'package:mobile/logging.dart';
import 'package:mobile/open/screens/mfa/mfa_step_chrome.dart';
import 'package:mobile/open/widgets/dg_app_bar.dart';
import 'package:mobile/open/widgets/dg_button.dart';
import 'package:mobile/open/widgets/dg_icon_button.dart';
import 'package:mobile/open/widgets/dg_mfa_step_label.dart';
import 'package:mobile/open/widgets/dg_text_form_field.dart';
import 'package:mobile/open/widgets/icons/dg_icon.dart';
import 'package:mobile/theme/color.dart';
import 'package:mobile/theme/spacing.dart';
import 'package:mobile/theme/text.dart';
import 'package:mobile/utils/error_handler.dart';

/// FIDO2 VPN MFA: the user enters the key's PIN and taps the key (NFC) or
/// plugs it in (USB, Android). The key signs Core's challenge for this MFA
/// attempt over the canonical client data of the instance's own origin.
class MfaFido2Screen extends HookConsumerWidget {
  final MfaStepHost host;

  /// The XGuard URL the device enrolled with; its domain is the relying party.
  final String instanceUrl;
  final Fido2CeremonyRunner? runner;

  const MfaFido2Screen({
    super.key,
    required this.host,
    required this.instanceUrl,
    this.runner,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final ceremony = useMemoized(() => runner ?? Fido2CeremonyRunner());
    final pinController = useTextEditingController();
    final busy = useState(false);
    final waitingForKey = useState(false);
    final message = useState<String?>(null);
    final nfcDisabled = useState(false);
    // A rejected or failed submission used the challenge up on Core.
    final needsNewChallenge = useRef(false);
    final mounted = useRef(true);

    useEffect(() {
      return () {
        mounted.value = false;
        if (waitingForKey.value) unawaited(ceremony.cancel());
      };
    }, const []);

    Future<void> abort() async {
      if (waitingForKey.value) await ceremony.cancel();
      host.abort();
    }

    Future<void> verify() async {
      if (busy.value) return;
      busy.value = true;
      message.value = null;
      nfcDisabled.value = false;
      try {
        if (needsNewChallenge.value) {
          try {
            await host.controller.reissueStep();
            needsNewChallenge.value = false;
          } catch (e) {
            if (reportIfAttemptLimit(host, e)) return;
            host.reportFailure(
              message: ErrorHandler.getHumanReadableError(e),
              logMessage: 'Failed to re-issue the FIDO2 step',
              error: e,
            );
            return;
          }
        }
        final challenge = host.controller.challenge;
        if (challenge == null) {
          host.reportFailure(
            message: 'The server sent no security key challenge. Start '
                'connecting again.',
            logMessage: 'FIDO2 step opened without a challenge',
          );
          return;
        }

        waitingForKey.value = true;
        final outcome = await ceremony.run(
          instanceUrl: instanceUrl,
          challenge: challenge,
          credentialIds: host.controller.credentialIds,
          pin: pinController.text,
        );
        if (!mounted.value) return;
        waitingForKey.value = false;

        switch (outcome) {
          case Fido2Problem(:final kind, :final detail):
            talker.warning('FIDO2 MFA: ${kind.name}${detail == null ? '' : ' ($detail)'}');
            if (kind == Fido2ProblemKind.cancelled && host.controller.isCancelled) {
              return;
            }
            if (!outcome.retryable) {
              host.reportFailure(
                message: outcome.message,
                logMessage: 'FIDO2 MFA failed: ${kind.name}',
              );
              return;
            }
            if (kind == Fido2ProblemKind.pinInvalid ||
                kind == Fido2ProblemKind.pinMissing ||
                kind == Fido2ProblemKind.pinTooShort ||
                kind == Fido2ProblemKind.pinTooLong) {
              pinController.clear();
            }
            nfcDisabled.value = kind == Fido2ProblemKind.nfcDisabled;
            message.value = outcome.message;
          case Fido2Signed(:final credential):
            pinController.clear();
            try {
              final progress = await host.controller.submit(
                credential: credential,
              );
              if (progress is MfaStepAwaiting) {
                throw StateError('FIDO2 step returned an out-of-band outcome');
              }
              host.reportProgress(progress);
            } catch (e) {
              needsNewChallenge.value = true;
              if (reportIfAttemptLimit(host, e)) return;
              talker.error('FIDO2 MFA answer refused', e);
              message.value = e is MfaCodeRejectedException
                  ? 'XGuard did not accept the security key. Make sure it is '
                        'the key registered for your account and try again.'
                  : ErrorHandler.getHumanReadableError(e);
            }
        }
      } finally {
        if (mounted.value) {
          busy.value = false;
          waitingForKey.value = false;
        }
      }
    }

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
              onTap: abort,
            ),
          ),
          body: SafeArea(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(20, 4, 20, 20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: SingleChildScrollView(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          DgMfaStepLabel(host.controller.stepLabel),
                          Text(
                            'Security key',
                            style: DgText.h4.copyWith(
                              color: DgColor.fgWhite100,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            waitingForKey.value
                                ? 'Hold your security key against the back of '
                                      'the phone, or plug it in, and touch it '
                                      'if it blinks.'
                                : 'Enter the PIN of your security key, then '
                                      'tap Verify.',
                            key: const Key('mfa_fido2_instructions'),
                            style: DgText.bodySm400.copyWith(
                              color: DgColor.fgWhite60,
                            ),
                          ),
                          const SizedBox(height: DgSpacing.xl2),
                          DgTextFormField(
                            identifier: 'mfa_fido2_pin',
                            label: 'Security key PIN',
                            controller: pinController,
                            obscureText: true,
                            disabled: busy.value,
                            onFieldSubmitted: (_) => verify(),
                          ),
                          if (message.value != null) ...[
                            const SizedBox(height: DgSpacing.lg),
                            Text(
                              message.value!,
                              key: const Key('mfa_fido2_message'),
                              style: DgText.bodySm400.copyWith(
                                color: DgColor.fgWhite80,
                              ),
                            ),
                          ],
                          if (nfcDisabled.value) ...[
                            const SizedBox(height: DgSpacing.md),
                            DgButton(
                              identifier: 'mfa_fido2_nfc_settings',
                              text: 'Open NFC settings',
                              style: DgButtonStyle.secondary,
                              size: DgButtonSize.primary,
                              onTap: () => unawaited(
                                const Fido2Plugin().openNfcSettings().catchError(
                                  (Object _) {},
                                ),
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: DgSpacing.xl),
                  DgButton(
                    identifier: 'mfa_fido2_verify',
                    text: waitingForKey.value ? 'Waiting for the key…' : 'Verify',
                    style: DgButtonStyle.primary,
                    size: DgButtonSize.big,
                    width: double.infinity,
                    loading: busy.value,
                    onTap: verify,
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
