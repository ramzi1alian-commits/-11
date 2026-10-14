package com.securekeyboard.app

import android.accessibilityservice.AccessibilityService
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Rect
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Base64
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.FrameLayout
import android.widget.TextView
import java.util.concurrent.Executors

/**
 * Shows decrypted text on top of encrypted messages inside chat apps, without any tap.
 *
 * How it works: on screen changes it reads the visible text nodes of the foreground chat
 * app, picks those that are entirely one long Base64 token, decrypts them with the same
 * session passphrase and paired contacts the keyboard uses, and draws the plaintext in a
 * non-touchable overlay exactly over the original bubble. Nothing is written into the
 * other app and nothing leaves the device (the app has no INTERNET permission).
 *
 * Deliberate limits:
 *  - Only acts when the foreground app is in [SUPPORTED_PACKAGES] (enforced here in code).
 *  - Never reads password fields; ignores everything that is not a whole-node Base64 token.
 *  - Never stores or logs screen content other than decrypted messages (encrypted cache).
 *  - Works only while the session passphrase is active (the 30-minute keyboard session).
 */
class AutoDecryptService : AccessibilityService() {

    companion object {
        /** Apps in which the overlay is active. Edit this list to add other chat apps. */
        private val SUPPORTED_PACKAGES = setOf(
            "com.whatsapp", "com.whatsapp.w4b",
            "org.telegram.messenger", "org.telegram.messenger.web",
            "org.thoughtcrime.securesms",
            "com.facebook.orca", "com.instagram.android",
            "com.viber.voip", "com.discord",
            "com.google.android.apps.messaging", "com.samsung.android.messaging", "com.android.mms"
        )
        private val TOKEN = Regex("^[A-Za-z0-9+/]{100,}={0,2}$")
        private val TOKEN_IN_TEXT = Regex("[A-Za-z0-9+/]{100,}={0,2}")
        private const val MIN_LEN = 100
        private const val MAX_LEN = 24_000
        private const val MAX_NODES = 1500
        private const val MAX_DEPTH = 40
        private const val MAX_TOKENS_PER_PASS = 40
        private const val MIN_REFRESH_INTERVAL_MS = 30L
        private const val EXPIRY_CHECK_MS = 2_000L
        private const val FAILURE_RETRY_MS = 5 * 60 * 1000L
    }

    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private var overlay: FrameLayout? = null

    // All three maps are touched on the main thread only.
    private val pending = HashSet<String>()
    private val retryAfter = HashMap<String, Long>()
    private val notices = HashMap<String, String>()

    private var refreshQueued = false
    private var lastRefreshAt = 0L
    private val refreshRunnable = Runnable {
        refreshQueued = false
        lastRefreshAt = SystemClock.uptimeMillis()
        refresh()
    }

    // While decrypted text is on screen, re-check the session key every couple of
    // seconds so the text disappears as soon as the key expires (even without any
    // screen event).
    private val expiryRunnable = Runnable {
        if (!SessionKeyStore.isActive()) {
            clearOverlay()
        } else if ((overlay?.childCount ?: 0) > 0) {
            scheduleExpiryCheck()
        }
    }

    private fun scheduleExpiryCheck() {
        main.removeCallbacks(expiryRunnable)
        main.postDelayed(expiryRunnable, EXPIRY_CHECK_MS)
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        SessionKeyStore.initialize(applicationContext)
        worker.execute {
            try { DecryptedMessageCache.preload(applicationContext) } catch (_: Exception) { }
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return
        // Our own windows (keyboard, this overlay) must never trigger work: no feedback loop.
        if (event.packageName?.toString() == packageName) return
        scheduleRefresh()
    }

    override fun onInterrupt() {
        clearOverlay()
    }

    override fun onDestroy() {
        main.removeCallbacksAndMessages(null)
        removeOverlayWindow()
        worker.shutdownNow()
        super.onDestroy()
    }

    private fun scheduleRefresh() {
        if (refreshQueued) return
        refreshQueued = true
        // Short throttle (not a long debounce) so the cards follow the bubbles while scrolling.
        val wait = (MIN_REFRESH_INTERVAL_MS - (SystemClock.uptimeMillis() - lastRefreshAt)).coerceAtLeast(0L)
        main.postDelayed(refreshRunnable, wait)
    }

    private fun refresh() {
        val root = try { rootInActiveWindow } catch (_: Exception) { null }
        if (root == null) {
            clearOverlay()
            return
        }
        try {
            val pkg = root.packageName?.toString()
            if (pkg == null || pkg !in SUPPORTED_PACKAGES) {
                clearOverlay()
                return
            }
            val found = ArrayList<Pair<String, Rect>>()
            collect(root, 0, IntArray(1), found)
            render(found)
        } catch (_: Exception) {
            clearOverlay()
        } finally {
            recycleNode(root)
        }
    }

    private fun collect(
        node: AccessibilityNodeInfo,
        depth: Int,
        counter: IntArray,
        out: MutableList<Pair<String, Rect>>
    ) {
        if (depth > MAX_DEPTH || counter[0] >= MAX_NODES || out.size >= MAX_TOKENS_PER_PASS) return
        counter[0]++
        if (depth > 0 && !node.isVisibleToUser) return
        if (!node.isPassword && node.isVisibleToUser) {
            // Some chat apps expose the whole bubble as one node ("name, message, time")
            // or put the message in contentDescription, so the token is searched for
            // inside the text instead of requiring the node to be only the token.
            val token = tokenFrom(node.text) ?: tokenFrom(node.contentDescription)
            if (token != null) {
                val rect = Rect()
                node.getBoundsInScreen(rect)
                if (rect.width() > 0 && rect.height() > 0) out.add(Pair(token, rect))
            }
        }
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            try {
                collect(child, depth + 1, counter, out)
            } finally {
                recycleNode(child)
            }
        }
    }

    /** Returns the Base64 ciphertext contained in [cs], or null. Wrapped lines are re-joined. */
    private fun tokenFrom(cs: CharSequence?): String? {
        if (cs == null || cs.length < MIN_LEN || cs.length > MAX_LEN) return null
        val s = cs.toString().trim()
        val joined = s.filterNot { it.isWhitespace() }
        if (TOKEN.matches(joined)) return joined
        val m = TOKEN_IN_TEXT.find(s) ?: return null
        return m.value.takeIf { it.length <= MAX_LEN }
    }

    private fun render(found: List<Pair<String, Rect>>) {
        // Once the session key has expired nothing is shown any more, not even messages
        // that were decrypted earlier and are still in the cache.
        if (!SessionKeyStore.isActive()) {
            clearOverlay()
            return
        }
        val toShow = ArrayList<Pair<Rect, String>>()
        for ((token, rect) in found) {
            val key = DecryptedMessageCache.keyOf(token)
            val text = DecryptedMessageCache.get(applicationContext, token) ?: notices[key]
            if (text != null) {
                toShow.add(Pair(rect, text))
            } else {
                requestDecrypt(token, key)
            }
        }
        if (toShow.isEmpty()) {
            clearOverlay()
            return
        }
        val container = ensureOverlay() ?: return
        // Reuse the existing card views (no remove/add churn) so scrolling stays smooth.
        while (container.childCount > toShow.size) container.removeViewAt(container.childCount - 1)
        for ((i, item) in toShow.withIndex()) {
            val existing = container.getChildAt(i) as? TextView
            if (existing == null) {
                val tv = TextView(this)
                bindCard(tv, item.first, item.second)
                container.addView(tv)
            } else {
                bindCard(existing, item.first, item.second)
            }
        }
        scheduleExpiryCheck()
    }

    private fun requestDecrypt(token: String, key: String) {
        if (pending.contains(key)) return
        val now = SystemClock.elapsedRealtime()
        val until = retryAfter[key]
        if (until != null && until > now) return
        if (!SessionKeyStore.isActive()) return
        pending.add(key)
        worker.execute {
            var plain: CharArray? = null
            var notice: String? = null
            val pass = SessionKeyStore.get()
            if (pass != null) {
                try {
                    val result = decryptToken(token, pass)
                    plain = result.first
                    notice = result.second
                } catch (_: Exception) {
                    // Treated as a failure below.
                } finally {
                    SecureMemory.wipe(pass)
                }
            }
            val success = plain != null
            val finalNotice: String? = notice
            if (plain != null) {
                try { DecryptedMessageCache.put(applicationContext, token, plain) } catch (_: Exception) { }
                SecureMemory.wipe(plain)
            }
            main.post {
                pending.remove(key)
                if (!success) {
                    if (finalNotice != null) {
                        notices[key] = finalNotice
                    } else {
                        retryAfter[key] = SystemClock.elapsedRealtime() + FAILURE_RETRY_MS
                    }
                }
                scheduleRefresh()
            }
        }
    }

    /** Returns (plaintext, notice). Mirrors the keyboard: contacts first, then passphrase-only. */
    private fun decryptToken(token: String, pass: CharArray): Pair<CharArray?, String?> {
        val raw = try {
            Base64.decode(token, Base64.NO_WRAP)
        } catch (_: Exception) {
            return Pair(null, null)
        }
        val version = if (raw.isNotEmpty()) raw[0].toInt() else -1
        SecureMemory.wipe(raw)
        if (version !in 2..4) return Pair(null, null)

        var expired = false
        var replayed = false
        for (name in ContactStore.listPairedContactNames(applicationContext)) {
            try {
                val keyB64 = ContactStore.getPairedContact(applicationContext, name) ?: continue
                val publicKey = DeviceIdentity.parseContactPublicKey(keyB64)
                return Pair(CryptoEngineV2.decrypt(applicationContext, token, pass, publicKey), null)
            } catch (_: CryptoEngineV2.ExpiredMessageException) {
                expired = true
                break
            } catch (_: CryptoEngineV2.ReplayedMessageException) {
                replayed = true
                break
            } catch (_: Exception) {
                // Not this contact; try the next one.
            }
        }
        if (expired) return Pair(null, getString(R.string.auto_decrypt_expired))
        if (replayed) return Pair(null, getString(R.string.auto_decrypt_replayed))
        if (version in 2..3) {
            try {
                return Pair(CryptoEngine.decrypt(token, pass), null)
            } catch (_: CryptoEngine.ExpiredMessageException) {
                return Pair(null, getString(R.string.auto_decrypt_expired))
            } catch (_: Exception) {
                // Not a passphrase-only message either.
            }
        }
        return Pair(null, null)
    }

    /**
     * Outgoing bubbles sit on the "end" side of the screen (right in LTR, left in RTL),
     * so the side with the smaller margin tells sent from received. Full-width bubbles
     * are treated as received.
     */
    private fun isOutgoing(rect: Rect): Boolean {
        val screenW = resources.displayMetrics.widthPixels
        val marginLeft = rect.left
        val marginRight = screenW - rect.right
        val rtl = resources.configuration.layoutDirection == View.LAYOUT_DIRECTION_RTL
        return if (rtl) marginLeft < marginRight else marginRight < marginLeft
    }

    private fun bindCard(tv: TextView, rect: Rect, text: String) {
        val night = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES
        val density = resources.displayMetrics.density
        val outgoing = isOutgoing(rect)
        // WhatsApp-like colours: sent = green, received = white (dark theme equivalents).
        val fill = when {
            outgoing && night -> "#005C4B"
            outgoing -> "#D9FDD3"
            night -> "#202C33"
            else -> "#FFFFFF"
        }
        val bg = GradientDrawable().apply {
            cornerRadius = 12f * density
            setColor(Color.parseColor(fill))
            setStroke((1.5f * density).toInt().coerceAtLeast(1), Color.parseColor("#2E7D32"))
        }
        tv.text = "\uD83D\uDD13 $text"
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
        tv.setTextColor(if (night) Color.parseColor("#E9EDEF") else Color.parseColor("#111B21"))
        tv.background = bg
        val pad = (8f * density).toInt()
        tv.setPadding(pad, pad, pad, pad)
        tv.minHeight = rect.height()
        val lp = (tv.layoutParams as? FrameLayout.LayoutParams)
            ?: FrameLayout.LayoutParams(rect.width(), FrameLayout.LayoutParams.WRAP_CONTENT)
        lp.width = rect.width()
        lp.height = FrameLayout.LayoutParams.WRAP_CONTENT
        lp.gravity = Gravity.TOP or Gravity.LEFT
        lp.leftMargin = rect.left
        lp.topMargin = rect.top
        tv.layoutParams = lp
    }

    private fun ensureOverlay(): FrameLayout? {
        overlay?.let { return it }
        return try {
            val wm = getSystemService(WINDOW_SERVICE) as WindowManager
            val lp = WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE or
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                    WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
                PixelFormat.TRANSLUCENT
            )
            lp.gravity = Gravity.TOP or Gravity.LEFT
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                lp.layoutInDisplayCutoutMode =
                    WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES
            }
            val container = FrameLayout(this)
            container.layoutDirection = View.LAYOUT_DIRECTION_LTR
            wm.addView(container, lp)
            overlay = container
            container
        } catch (_: Exception) {
            null
        }
    }

    private fun clearOverlay() {
        overlay?.removeAllViews()
    }

    private fun removeOverlayWindow() {
        val c = overlay ?: return
        overlay = null
        try {
            (getSystemService(WINDOW_SERVICE) as WindowManager).removeView(c)
        } catch (_: Exception) {
        }
    }

    @Suppress("DEPRECATION")
    private fun recycleNode(node: AccessibilityNodeInfo?) {
        try { node?.recycle() } catch (_: Exception) { }
    }
}
