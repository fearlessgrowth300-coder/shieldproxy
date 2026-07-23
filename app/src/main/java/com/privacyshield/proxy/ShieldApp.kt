package com.privacyshield.proxy

import android.app.Application
import com.privacyshield.proxy.core.CrashReporter
import com.privacyshield.proxy.core.Supabase

/**
 * App entry point. Installs the privacy-safe crash handler before any activity starts and flushes
 * queued reports without blocking startup.
 */
class ShieldApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Supabase.retryPendingLogoutAsync(this)
        CrashReporter.install(this)
        CrashReporter.flushAsync(this)
    }
}
