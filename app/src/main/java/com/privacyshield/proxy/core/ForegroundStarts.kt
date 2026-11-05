package com.privacyshield.proxy.core

import android.app.Notification
import android.app.Service
import android.content.pm.ServiceInfo
import android.os.Build

/** API 34+ rejects startForeground() unless the manifest type is passed again. */
object ForegroundStarts {
    fun start(service: Service, id: Int, notification: Notification, type: Int) {
        if (Build.VERSION.SDK_INT >= 34) {
            service.startForeground(id, notification, type)
        } else {
            service.startForeground(id, notification)
        }
    }

    const val SPECIAL_USE = ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
    const val DATA_SYNC = ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
}
