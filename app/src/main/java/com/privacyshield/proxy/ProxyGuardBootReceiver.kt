package com.privacyshield.proxy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Restores the encrypted proxy guard after a normal reboot or an in-place app update. */
class ProxyGuardBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (intent.action == Intent.ACTION_MY_PACKAGE_REPLACED && VpnConsent.isWanted(context)) {
            // The in-app updater and adb install -r clear VPN consent. Start only when
            // the system dialog is not required; otherwise the home screen asks for it.
            android.util.Log.i("ShieldVpn", "step=update-restart")
            VpnConsent.startIfPrepared(context)
        }
        runCatching { ProxyGuardService.restorePersisted(context) }
            .onFailure { android.util.Log.e("ProxyGuardBoot", "Could not restore proxy guard", it) }
    }
}
