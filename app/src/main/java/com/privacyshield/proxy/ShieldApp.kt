package com.privacyshield.proxy

import android.app.Application
import android.os.Build
import com.privacyshield.proxy.core.CrashReporter
import com.privacyshield.proxy.core.ProfileScopeGuard
import com.privacyshield.proxy.core.ProfileStatus
import com.privacyshield.proxy.core.Supabase
import java.io.File

/**
 * App entry point. Installs the privacy-safe crash handler before any activity starts and flushes
 * queued reports without blocking startup.
 *
 * The :vpn process must reach startForeground() within a few seconds of
 * startForegroundService(). Verifying Supabase, crash reporting, and profile status on that
 * cold start blew the limit on API 31+, so this process stays empty until the service runs.
 */
class ShieldApp : Application() {
    override fun onCreate() {
        super.onCreate()
        if (isVpnProcess()) return
        // Separate method so the :vpn process never resolves these classes.
        // Verifying them inline blew the foreground-service deadline.
        startUiProcess()
    }

    private fun startUiProcess() {
        ProfileScopeGuard.enforce(this)
        ProfileStatus.note(this, "", "", 0, "")
        Supabase.retryPendingLogoutAsync(this)
        CrashReporter.install(this)
        CrashReporter.flushAsync(this)
    }

    private fun isVpnProcess(): Boolean {
        val name = if (Build.VERSION.SDK_INT >= 28) {
            getProcessName()
        } else {
            runCatching {
                File("/proc/self/cmdline").readText().substringBefore('\u0000')
            }.getOrDefault("")
        }
        return name.endsWith(":vpn")
    }
}
