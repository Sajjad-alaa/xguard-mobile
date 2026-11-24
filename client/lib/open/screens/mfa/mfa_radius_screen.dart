import 'dart:async';

import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mobile/data/mfa/mfa_flow.dart';
import 'package:mobile/data/mfa/mfa_transport.dart';
import 'package:mobile/data/proxy/mfa.dart';
import 'package:mobile/open/screens/mfa/mfa_step_chrome.dart';
import 'package:mobile/open/widgets/dg_app_bar.dart';
import 'package:mobile/open/widgets/dg_button.dart';
import 'package:mobile/open/widgets/dg_icon_button.dart';
import 'package:mobile/open/widgets/dg_mfa_step_label.dart';
import 'package:mobile/open/widgets/dg_text_form_field.dart';
import 'package:mobile/open/widgets/icons/dg_icon.dart';
import 'package:mobile/open/widgets/toaster/toast_manager.dart';
import 'package:mobile/theme/color.dart';
import 'package:mobile/theme/text.dart';
import 'package:mobile/utils/error_handler.dart';

class MfaRadiusScreen extends HookConsumerWidget {
  final MfaStepHost host;

  const MfaRadiusScreen({super.key, required this.host});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final toaster = ref.read(toastManagerProvider.notifier);
    final codeController = useTextEditingController();
    final isLoading = useState(false);
    final errorText = useState<String?>(null);
    final challenge = useState<MfaStepRadiusChallenge?>(null);
    final pollingInFlight = useRef(false);

    Future<void> submitCredential(MfaCredential? credential) async {
      final isPoll = credential == null;
      if (isPoll) {
        if (pollingInFlight.value) return;
        pollingInFlight.value = true;
      } else {
        errorText.value = null;
        isLoading.value = true;
      }

      try {
        final progress = await host.controller.submit(credential: credential);
        if (!context.mounted) return;
        switch (progress) {
          case MfaStepRadiusChallenge():
            challenge.value = progress;
            codeController.clear();
            errorText.value = null;
          case MfaStepAwaiting():
            // Push approval still pending; keep polling.
            break;
          case MfaStepAdvanced():
          case MfaStepCompleted():
            challenge.value = null;
            host.reportProgress(progress);
        }
      } on MfaCodeRejectedException {
        if (context.mounted) {
          challenge.value = null;
          errorText.value = 'Invalid RADIUS code';
        }
      } catch (e) {
        if (reportIfPostureRejected(host, e) || reportIfAttemptLimit(host, e)) {
          return;
        }
        if (!isPoll && context.mounted) {
          toaster.showError(
            message: ErrorHandler.getHumanReadableError(e),
            logMessage: 'RADIUS MFA submit failed',
            error: e,
          );
        }
      } finally {
        if (isPoll) {
          pollingInFlight.value = false;
        } else if (context.mounted) {
          isLoading.value = false;
        }
      }
    }

    final activeChallenge = challenge.value;
    useEffect(() {
      if (activeChallenge == null || !activeChallenge.push) return null;
      final intervalSecs = activeChallenge.pollIntervalSecs > 0
          ? activeChallenge.pollIntervalSecs
          : 2;
      final timer = Timer.periodic(
        Duration(seconds: intervalSecs),
        (_) => unawaited(submitCredential(null)),
      );
      return timer.cancel;
    }, [activeChallenge?.push, activeChallenge?.pollIntervalSecs]);

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
          body: CustomScrollView(
            physics: const ClampingScrollPhysics(),
            slivers: [
              SliverFillRemaining(
                hasScrollBody: false,
                child: SafeArea(
                  bottom: true,
                  top: false,
                  child: Padding(
                    padding: const EdgeInsets.only(
                      top: 4,
                      left: 20,
                      right: 20,
                      bottom: 20,
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        DgMfaStepLabel(host.controller.stepLabel),
                        Text(
                          'RADIUS authentication',
                          style: DgText.h4.copyWith(color: DgColor.fgWhite100),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Enter your RADIUS one-time code, or trigger an SMS / push approval challenge.',
                          style: DgText.bodySm400.copyWith(
                            color: DgColor.fgWhite60,
                          ),
                        ),
                        if (activeChallenge != null) ...[
                          const SizedBox(height: 20),
                          Container(
                            width: double.infinity,
                            padding: const EdgeInsets.all(14),
                            decoration: BoxDecoration(
                              color: DgColor.fgWhite100.withValues(alpha: 0.08),
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(
                                color: DgColor.fgWhite100.withValues(
                                  alpha: 0.18,
                                ),
                              ),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  activeChallenge.message.isNotEmpty
                                      ? activeChallenge.message
                                      : (activeChallenge.push
                                            ? 'Approve the sign-in request on your device, or enter a code below.'
                                            : 'Enter the response requested by your RADIUS server.'),
                                  style: DgText.bodySm400.copyWith(
                                    color: DgColor.fgWhite100,
                                  ),
                                ),
                                if (activeChallenge.push) ...[
                                  const SizedBox(height: 10),
                                  Row(
                                    children: [
                                      const SizedBox(
                                        width: 14,
                                        height: 14,
                                        child: CircularProgressIndicator(
                                          strokeWidth: 2,
                                        ),
                                      ),
                                      const SizedBox(width: 8),
                                      Expanded(
                                        child: Text(
                                          'Waiting for push approval…',
                                          style: DgText.bodySm400.copyWith(
                                            color: DgColor.fgWhite60,
                                          ),
                                        ),
                                      ),
                                    ],
                                  ),
                                ],
                              ],
                            ),
                          ),
                        ],
                        const SizedBox(height: 24),
                        DgTextFormField(
                          identifier: 'mfa_radius_code_input',
                          required: false,
                          size: .big,
                          label: 'RADIUS Code / PIN+OTP',
                          controller: codeController,
                          errorText: errorText.value,
                          onChanged: (_) => errorText.value = null,
                          keyboardType: TextInputType.text,
                        ),
                        const Spacer(),
                        const SizedBox(height: 20),
                        if (activeChallenge == null ||
                            !activeChallenge.push) ...[
                          DgButton(
                            identifier: 'mfa_radius_challenge_trigger',
                            text: 'Send SMS / Push Challenge',
                            width: double.infinity,
                            disabled: isLoading.value,
                            onTap: () => unawaited(
                              submitCredential(const MfaCodeCredential('')),
                            ),
                          ),
                          const SizedBox(height: 12),
                        ],
                        DgButton(
                          identifier: 'mfa_radius_submit',
                          text: 'Submit',
                          loading: isLoading.value,
                          width: double.infinity,
                          onTap: () => unawaited(
                            submitCredential(
                              MfaCodeCredential(codeController.text.trim()),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
