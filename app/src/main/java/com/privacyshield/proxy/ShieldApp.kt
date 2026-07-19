package com.privacyshield.proxy

import android.app.Application
import com.privacyshield.proxy.core.CrashReporter
import com.privacyshield.proxy.core.RemoteControl
import com.privacyshield.proxy.core.Supabase

/**
 * App entry point. Installs the privacy-safe crash handler before any activity starts, honors a
 * remote kill flag on cold start, and flushes any queued crash reports.
 */
class ShieldApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Supabase.retryPendingLogoutAsync(this)
        CrashReporter.install(this)
        RemoteControl.checkAsync(this)   // fail-safe: enforce an armed kill switch immediately
        CrashReporter.flushAsync(this)
    }
}
