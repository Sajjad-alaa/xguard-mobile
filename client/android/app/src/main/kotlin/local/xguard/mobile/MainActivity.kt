package local.xguard.mobile

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterFragmentActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        // XGuard device posture: read-only facts, no permission needed.
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "local.xguard.mobile/posture")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "facts" -> result.success(postureFacts())
                    else -> result.notImplemented()
                }
            }
    }

    private fun postureFacts(): Map<String, Any?> {
        val keyguard = getSystemService(KeyguardManager::class.java)
        val policy = getSystemService(DevicePolicyManager::class.java)
        return mapOf(
            "deviceSecure" to runCatching { keyguard?.isDeviceSecure }.getOrNull(),
            "encryptionStatus" to runCatching { policy?.storageEncryptionStatus }.getOrNull(),
        )
    }
}
