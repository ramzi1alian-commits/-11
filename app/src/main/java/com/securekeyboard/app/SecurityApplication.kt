package com.securekeyboard.app

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.view.WindowManager

/**
 * Initializes the local runtime security monitor. No secrets or user input
 * are logged. The posture is exposed only through SecurityRuntime for
 * sensitive screens to consult before cryptographic actions.
 *
 * Also applies two protections to EVERY screen of the app:
 *  - FLAG_SECURE: no screenshots / screen recording / Recents thumbnails.
 *  - filterTouchesWhenObscured: touches are dropped while another app draws
 *    an overlay on top (tapjacking / clickjacking defence).
 */
class SecurityApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Do not emit the posture to logcat: a hardened build should minimize
        // useful security telemetry available to local attackers.
        SecurityRuntime.assess(this)
        // V61: restore the persisted session key in EVERY process start. Until now only the keyboard / some
        // screens did it, so a file opened straight from WhatsApp in a fresh process saw "no active session key".
        try { SessionKeyStore.initialize(this) } catch (_: Throwable) {}
        // V65: housekeeping off the main thread - encrypted files already handed to a chat app are deleted after
        // 24 h, plaintext working copies / inbox files after 1 h.
        Thread {
            try {
                val cutoff = System.currentTimeMillis() - 24L * 60L * 60L * 1000L
                java.io.File(filesDir, "secure_outbox").listFiles()?.forEach { if (it.lastModified() < cutoff) it.delete() }
                AttachmentStore.purgeOld(this)
                FileTextTransport.purgeOld(this)
            } catch (_: Throwable) {}
        }.apply { isDaemon = true }.start()
        // Start every screen in the day/night configuration of the saved palette.
        ThemeUtil.syncNightMode(this)
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                activity.window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
            }
            override fun onActivityResumed(activity: Activity) {
                try { activity.window.decorView.filterTouchesWhenObscured = true } catch (_: Throwable) {}
            }
            override fun onActivityStarted(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivityStopped(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }
}
