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
import java.util.concurrent.RejectedExecutionException

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
 *  - Battery: only RECENT messages are decrypted. When a chat is opened (or the key is set)
 *    only the newest [RECENT_AT_OPEN] ciphertexts on screen are decrypted, plus any message
 *    that then arrives below the ones already seen. Older history, and messages revealed by
 *    scrolling up, are NOT decrypted (a cheap cache lookup still shows ones already opened with
 *    this key). A message that failed is not retried during the session, and scans slow down
 *    when no ciphertext is on screen.
 *  - Everything shown is bound to the passphrase that is active RIGHT NOW (see
 *    [DecryptedMessageCache.fingerprintOf]). When the key changes, earlier plaintexts
 *    disappear, and every failure/notice remembered for the old key is forgotten so
 *    messages are tried again with the new one.
 *
 * Smooth scrolling: the screen scan (IPC-heavy) runs on its own thread; the main thread only
 * moves ready-made cards. Between scans the cards are shifted by the scroll delta that the
 * scroll event reports, so they follow the bubbles instead of jumping every ~100 ms.
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
        private val TOKEN = Regex("^(?:Ag|Aw|BA|Bg|Bw)[A-Za-z0-9+/]{42,}={0,2}$")
        private val TOKEN_IN_TEXT = Regex("(?:Ag|Aw|BA|Bg|Bw)[A-Za-z0-9+/]{42,}={0,2}")
        // Smallest real message is the compact v7 format with 1 char of text: 36 bytes = 48 Base64 chars.
        private const val MIN_LEN = 44
        private const val MAX_LEN = 24_000
        private const val MAX_NODES = 1500
        private const val MAX_DEPTH = 40
        private const val MAX_TOKENS_PER_PASS = 40
        private const val MIN_REFRESH_INTERVAL_MS = 30L
        private const val EXPIRY_CHECK_MS = 2_000L
        // A wrong-key failure would fail the same way again (and each try costs a full Argon2id),
        // so it is not retried for the length of a session.
        private const val FAILURE_RETRY_MS = 30 * 60 * 1000L
        // Only this many ciphertexts (the newest on screen) are decrypted when a chat is opened.
        private const val RECENT_AT_OPEN = 3
        // Scan interval while no ciphertext is on screen (cards on screen use the short one).
        private const val IDLE_REFRESH_INTERVAL_MS = 300L
    }

    private val main = Handler(Looper.getMainLooper())
    // Decryption (Argon2, can take long) must never delay screen scans, so they get separate threads.
    private val decryptor = Executors.newSingleThreadExecutor()
    private val scanner = Executors.newSingleThreadExecutor()
    private var overlay: FrameLayout? = null

    /** One visible ciphertext. [id] = ciphertext hash + key fingerprint, so state is per key. */
    private class ScanItem(val token: String, val id: String, val rect: Rect)

    /** [fp] is null when no session key is active. */
    private class ScanResult(val fp: String?, val items: List<ScanItem>)

    private class CardState(var text: String, var style: Int, var width: Int, var minHeight: Int)

    // All of this is touched on the main thread only.
    private var currentFp: String? = null
    private val memo = HashMap<String, String>()          // id -> plaintext ready to draw
    private val pending = HashSet<String>()               // id -> decryption in flight
    private val retryAfter = HashMap<String, Long>()      // id -> do not retry before
    private val notices = HashMap<String, String>()       // id -> "expired" / "already opened" / "bad text"
    private val failures = HashMap<String, String>()      // id -> "wrong key" (retried later)
    // Recency policy (see class doc): which ciphertexts were already classified, which of them
    // may be decrypted, and which only had a cache lookup.
    private val seen = HashSet<String>()
    private val eligible = HashSet<String>()
    private val cacheChecked = HashSet<String>()
    // True when the next new ciphertexts on screen count as "a chat was just opened".
    private var allowOpenBatch = true
    private var lastHadTokens = false

    private var scanQueued = false
    private var scanRunning = false
    private var scanDirty = false
    private var lastRefreshAt = 0L
    // Total vertical scroll (px) reported by scroll events so far; used to correct scan results
    // that were taken before the latest scroll.
    private var shiftY = 0
    private var originX = 0
    private var overlayAddedAt = 0L
    private var originY = 0

    private val scanRunnable = Runnable {
        scanQueued = false
        lastRefreshAt = SystemClock.uptimeMillis()
        startScan()
    }

    // While decrypted text is on screen, re-check the session key every couple of
    // seconds so the text disappears as soon as the key expires (even without any
    // screen event).
    private val expiryRunnable = Runnable {
        if (!SessionKeyStore.isActive()) {
            // Drop all plaintext now; the next scan shows "choose a key first" cards instead.
            wipeState()
            clearOverlay()
            scheduleRefresh()
        } else if ((overlay?.childCount ?: 0) > 0) {
            scheduleExpiryCheck()
        }
    }

    private fun scheduleExpiryCheck() {
        main.removeCallbacks(expiryRunnable)
        main.postDelayed(expiryRunnable, EXPIRY_CHECK_MS)
    }

    /** Forget everything tied to a key (plaintext in memory, failures, notices). */
    private fun wipeState() {
        currentFp = null
        memo.clear()
        pending.clear()
        retryAfter.clear()
        notices.clear()
        failures.clear()
        seen.clear()
        eligible.clear()
        cacheChecked.clear()
        allowOpenBatch = true
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        SessionKeyStore.initialize(applicationContext)
        decryptor.execute {
            try { DecryptedMessageCache.preload(applicationContext) } catch (_: Exception) { }
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return
        // Our own windows (keyboard, this overlay) must never trigger work: no feedback loop.
        if (event.packageName?.toString() == packageName) return
        // A new screen/activity (e.g. a chat was opened): its newest messages are "recent".
        if (event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) allowOpenBatch = true
        if (event.eventType == AccessibilityEvent.TYPE_VIEW_SCROLLED &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
        ) {
            val cls = event.className?.toString() ?: ""
            val dy = event.scrollDeltaY
            if (dy != 0 && !cls.contains("Horizontal") && !cls.contains("ViewPager") &&
                Math.abs(dy) < resources.displayMetrics.heightPixels
            ) {
                applyScrollShift(dy)
            }
        }
        scheduleRefresh()
    }

    /** Content moved up by [dy] px: move the cards with it right away, before the next scan. */
    private fun applyScrollShift(dy: Int) {
        shiftY += dy
        val c = overlay ?: return
        for (i in 0 until c.childCount) {
            val v = c.getChildAt(i)
            v.translationY = v.translationY - dy
        }
    }

    override fun onInterrupt() {
        clearOverlay()
    }

    override fun onDestroy() {
        main.removeCallbacksAndMessages(null)
        removeOverlayWindow()
        wipeState()
        decryptor.shutdownNow()
        scanner.shutdownNow()
        super.onDestroy()
    }

    private fun scheduleRefresh() {
        if (scanRunning) {
            scanDirty = true
            return
        }
        if (scanQueued) return
        scanQueued = true
        // Short throttle (not a long debounce) so the cards follow the bubbles while scrolling.
        val interval = if (lastHadTokens || (overlay?.childCount ?: 0) > 0) MIN_REFRESH_INTERVAL_MS else IDLE_REFRESH_INTERVAL_MS
        val wait = (interval - (SystemClock.uptimeMillis() - lastRefreshAt)).coerceAtLeast(0L)
        main.postDelayed(scanRunnable, wait)
    }

    private fun startScan() {
        scanRunning = true
        scanDirty = false
        val shiftAtStart = shiftY
        try {
            scanner.execute {
                val result = try { scan() } catch (_: Exception) { null }
                main.post {
                    scanRunning = false
                    onScanResult(result, shiftAtStart)
                    if (scanDirty) scheduleRefresh()
                }
            }
        } catch (_: RejectedExecutionException) {
            scanRunning = false
        }
    }

    /** Runs on the scanner thread. */
    private fun scan(): ScanResult {
        // The active key's fingerprint decides what may be shown and what state is valid.
        val pass = SessionKeyStore.get()
        // null = no active key; messages are still located so a "choose a key first" card can be shown.
        val fp = if (pass == null) null else try {
            DecryptedMessageCache.fingerprintOf(pass)
        } finally {
            SecureMemory.wipe(pass)
        }
        val root = try { rootInActiveWindow } catch (_: Exception) { null }
            ?: return ScanResult(fp, emptyList())
        try {
            val pkg = root.packageName?.toString()
            if (pkg == null || pkg !in SUPPORTED_PACKAGES) return ScanResult(fp, emptyList())
            val found = ArrayList<Pair<String, Rect>>()
            collect(root, 0, IntArray(1), found)
            val items = ArrayList<ScanItem>(found.size)
            for ((token, rect) in found) {
                items.add(ScanItem(token, DecryptedMessageCache.keyOf(token) + (fp ?: ""), rect))
            }
            return ScanResult(fp, items)
        } finally {
            recycleNode(root)
        }
    }

    private fun onScanResult(result: ScanResult?, shiftAtStart: Int) {
        val fp = result?.fp
        if (result == null) {
            wipeState()
            clearOverlay()
            return
        }
        lastHadTokens = result.items.isNotEmpty()
        // A screen without any ciphertext (chat list, other app): the next ones are a fresh opening.
        if (!lastHadTokens) allowOpenBatch = true
        if (fp == null) {
            // No active key (expired, cleared or never chosen): drop all plaintext and tell the user.
            wipeState()
            render(result.items, null, shiftY - shiftAtStart)
            return
        }
        if (fp != currentFp) {
            // The key changed: nothing remembered for the old key may be reused or blocked.
            wipeState()
            currentFp = fp
        }
        render(result.items, fp, shiftY - shiftAtStart)
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

    /**
     * Recency policy. Called for every scan result while a key is active. A ciphertext is
     * decrypted only if, the first time it is seen, it is
     *  - among the newest [RECENT_AT_OPEN] on screen right after a chat was opened / the key set, or
     *  - BELOW every ciphertext already seen (a message that just arrived).
     * Everything else (old history, or older messages revealed by scrolling up) is remembered as
     * seen-but-not-eligible and never decrypted automatically.
     */
    private fun classifyNew(items: List<ScanItem>) {
        var anyKnown = false
        var maxKnownBottom = Int.MIN_VALUE
        val unseen = ArrayList<ScanItem>()
        for (item in items) {
            if (seen.contains(item.id)) {
                anyKnown = true
                if (item.rect.bottom > maxKnownBottom) maxKnownBottom = item.rect.bottom
            } else {
                unseen.add(item)
            }
        }
        if (unseen.isEmpty()) return
        if (anyKnown) {
            for (u in unseen) if (u.rect.bottom > maxKnownBottom) eligible.add(u.id)
        } else if (allowOpenBatch) {
            allowOpenBatch = false
            for (u in unseen.sortedByDescending { it.rect.bottom }.take(RECENT_AT_OPEN)) eligible.add(u.id)
        }
        for (u in unseen) seen.add(u.id)
    }

    /** Cheap, no key derivation: shows a message that was already opened with this key. */
    private fun requestCacheLookup(item: ScanItem, fp: String) {
        val id = item.id
        if (!cacheChecked.add(id)) return
        val token = item.token
        try {
            decryptor.execute {
                val text = try {
                    DecryptedMessageCache.get(applicationContext, token, fp)
                } catch (_: Exception) {
                    null
                }
                if (text != null) {
                    main.post {
                        if (currentFp == fp) {
                            memo[id] = text
                            scheduleRefresh()
                        }
                    }
                }
            }
        } catch (_: RejectedExecutionException) {
            cacheChecked.remove(id)
        }
    }

    private fun render(items: List<ScanItem>, fp: String?, scrolledSinceScan: Int) {
        if (fp != null) classifyNew(items)
        val toShow = ArrayList<Pair<Rect, String>>()
        for (item in items) {
            if (fp == null) {
                toShow.add(Pair(item.rect, getString(R.string.auto_decrypt_no_key)))
                continue
            }
            val done = memo[item.id] ?: notices[item.id]
            // Messages that failed are re-tried later (rate-limited), without hiding the status card.
            if (done == null) {
                if (eligible.contains(item.id)) requestDecrypt(item, fp) else requestCacheLookup(item, fp)
            }
            // Always show SOMETHING: result, status, or "decrypting..." while Argon2 is running.
            val text = done ?: failures[item.id]
                ?: (if (pending.contains(item.id)) getString(R.string.auto_decrypt_working) else null)
            if (text != null) toShow.add(Pair(item.rect, text))
        }
        if (toShow.isEmpty()) {
            clearOverlay()
            return
        }
        val container = ensureOverlay() ?: return
        // Positions from accessibility are SCREEN coordinates, but the overlay window is not
        // guaranteed to start at the screen's top-left (cutout / system bars / Android 14
        // insets). Same trap as the keyboard's key popup: subtract the window's own origin.
        val origin = IntArray(2)
        try { container.getLocationOnScreen(origin) } catch (_: Exception) { }
        originX = origin[0]
        originY = origin[1]
        // Reuse the existing card views (no remove/add churn) so scrolling stays smooth.
        while (container.childCount > toShow.size) container.removeViewAt(container.childCount - 1)
        for ((i, item) in toShow.withIndex()) {
            val existing = container.getChildAt(i) as? TextView
            if (existing == null) {
                val tv = TextView(this)
                tv.layoutParams = FrameLayout.LayoutParams(
                    item.first.width(), FrameLayout.LayoutParams.WRAP_CONTENT, Gravity.TOP or Gravity.LEFT
                )
                bindCard(tv, item.first, item.second, scrolledSinceScan)
                container.addView(tv)
            } else {
                bindCard(existing, item.first, item.second, scrolledSinceScan)
            }
        }
        if (fp != null) scheduleExpiryCheck()
    }

    private fun requestDecrypt(item: ScanItem, fp: String) {
        val id = item.id
        if (pending.contains(id)) return
        val now = SystemClock.elapsedRealtime()
        val until = retryAfter[id]
        if (until != null && until > now) return
        pending.add(id)
        val token = item.token
        try {
            decryptor.execute {
                var text: String? = null
                var notice: String? = null
                var failed = false
                try {
                    // Already decrypted under THIS key (also covers a message opened by the keyboard).
                    text = DecryptedMessageCache.get(applicationContext, token, fp)
                    if (text == null) {
                        val pass = SessionKeyStore.get()
                        if (pass != null) {
                            try {
                                // The key may have been changed while this job waited in the queue.
                                if (DecryptedMessageCache.fingerprintOf(pass) == fp) {
                                    var plain: CharArray? = null
                                    try {
                                        val result = decryptToken(token, pass)
                                        plain = result.first
                                        notice = result.second
                                        if (plain != null) {
                                            text = String(plain)
                                            try {
                                                DecryptedMessageCache.put(applicationContext, token, plain, fp)
                                            } catch (_: Exception) { }
                                        } else if (notice == null) {
                                            failed = true
                                        }
                                    } catch (_: Exception) {
                                        failed = true
                                    } finally {
                                        SecureMemory.wipe(plain)
                                    }
                                }
                            } finally {
                                SecureMemory.wipe(pass)
                            }
                        }
                    }
                } catch (_: Exception) {
                    failed = true
                }
                val finalText = text
                val finalNotice = notice
                val finalFailed = failed
                main.post {
                    pending.remove(id)
                    // Only results for the key that is still active are kept.
                    if (currentFp == fp) {
                        when {
                            finalText != null -> { memo[id] = finalText; failures.remove(id) }
                            finalNotice != null -> notices[id] = finalNotice
                            finalFailed -> {
                                failures[id] = getString(R.string.auto_decrypt_wrong_key)
                                retryAfter[id] = SystemClock.elapsedRealtime() + FAILURE_RETRY_MS
                            }
                        }
                    }
                    scheduleRefresh()
                }
            }
        } catch (_: RejectedExecutionException) {
            pending.remove(id)
        }
    }

    /** Returns (plaintext, notice). Mirrors the keyboard: contacts first, then passphrase-only. */
    private fun decryptToken(token: String, pass: CharArray): Pair<CharArray?, String?> {
        val raw = try {
            Base64.decode(token, Base64.NO_WRAP)
        } catch (_: Exception) {
            return Pair(null, getString(R.string.auto_decrypt_bad_text))
        }
        val version = if (raw.isNotEmpty()) raw[0].toInt() else -1
        SecureMemory.wipe(raw)
        if (version !in 2..7) return Pair(null, getString(R.string.auto_decrypt_bad_text))

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
        // Passphrase-only messages: legacy v2/v3 AND the current compact v7 format. This used
        // to be gated to versions 2..3, so every NEW passphrase-only message (v7) was never
        // tried and always showed "cannot decrypt". The keyboard's own decrypt has no such
        // gate; mirror it. Contact messages (v6) are already handled above, and
        // CryptoEngine.decrypt rejects an unsupported version before any costly key derivation.
        try {
            return Pair(CryptoEngine.decrypt(token, pass), null)
        } catch (_: CryptoEngine.ExpiredMessageException) {
            return Pair(null, getString(R.string.auto_decrypt_expired))
        } catch (_: Exception) {
            // Not a passphrase-only message either.
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

    private fun bindCard(tv: TextView, rect: Rect, text: String, scrolledSinceScan: Int) {
        val night = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES
        val density = resources.displayMetrics.density
        val outgoing = isOutgoing(rect)
        val style = (if (night) 2 else 0) + (if (outgoing) 1 else 0)
        val state = tv.tag as? CardState
        // Only touch what actually changed: re-setting text/background/padding on every
        // scan forces a new layout pass per card and is what made scrolling stutter.
        if (state == null || state.style != style) {
            // WhatsApp-like colours: sent = green, received = white (dark theme equivalents).
            val fill = when {
                outgoing && night -> "#005C4B"
                outgoing -> "#D9FDD3"
                night -> "#202C33"
                else -> "#FFFFFF"
            }
            tv.background = GradientDrawable().apply {
                cornerRadius = 12f * density
                setColor(Color.parseColor(fill))
                setStroke((1.5f * density).toInt().coerceAtLeast(1), Color.parseColor("#2E7D32"))
            }
            tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
            tv.setTextColor(if (night) Color.parseColor("#E9EDEF") else Color.parseColor("#111B21"))
            val pad = (8f * density).toInt()
            tv.setPadding(pad, pad, pad, pad)
        }
        if (state == null || state.text != text) {
            tv.text = "\uD83D\uDD13 $text"
        }
        if (state == null || state.minHeight != rect.height()) {
            tv.minHeight = rect.height()
        }
        if (state == null || state.width != rect.width()) {
            val lp = (tv.layoutParams as? FrameLayout.LayoutParams)
                ?: FrameLayout.LayoutParams(rect.width(), FrameLayout.LayoutParams.WRAP_CONTENT)
            lp.width = rect.width()
            lp.height = FrameLayout.LayoutParams.WRAP_CONTENT
            lp.gravity = Gravity.TOP or Gravity.LEFT
            tv.layoutParams = lp
        }
        tv.tag = CardState(text, style, rect.width(), rect.height())
        // Position through translation: moving a card never triggers a layout pass.
        tv.translationX = (rect.left - originX).toFloat()
        tv.translationY = (rect.top - originY - scrolledSinceScan).toFloat()
    }

    private fun ensureOverlay(): FrameLayout? {
        overlay?.let {
            // A freshly added window attaches on its first frame, so only judge older ones.
            if (it.isAttachedToWindow || SystemClock.uptimeMillis() - overlayAddedAt < 1000L) return it
            // The window was dropped by the system (service rebind, display change): rebuild it,
            // otherwise cards would be added to a dead window and never appear.
            overlay = null
            try { (getSystemService(WINDOW_SERVICE) as WindowManager).removeViewImmediate(it) } catch (_: Exception) { }
        }
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
            overlayAddedAt = SystemClock.uptimeMillis()
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
