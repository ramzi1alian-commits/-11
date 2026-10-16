package com.securekeyboard.app

import android.content.Context
import android.util.Base64
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * ClipboardHistory (V63) - OPT-IN, off by default (Settings switch).
 *
 * A permanent, searchable history of text copied while the keyboard is running, for the NORMAL keyboard only
 * (never captured in secure-compose / crypto screens). Up to [MAX_ITEMS] entries, newest first; pinned
 * entries are never evicted. Stored ONLY on this device, encrypted with LocalStorageCrypto (Android Keystore
 * AES-GCM) like the learned-words file; never sent anywhere (the app has no INTERNET permission).
 *
 * Never stored: clips flagged sensitive by the source app (password managers), this app's own copied
 * results, anything that looks like one of this app's encrypted messages / a long token or key, anything that
 * looks like a card number, blank text, and text longer than [MAX_ITEM_CHARS].
 */
object ClipboardHistory {

    class Clip(val text: String, val time: Long, var pinned: Boolean)

    private const val FILE_NAME = "clipboard_history.bin"
    const val MAX_ITEMS = 5000
    private const val MAX_ITEM_CHARS = 20_000
    private const val MAX_TOTAL_CHARS = 4_000_000

    private val items = ArrayList<Clip>()           // newest first, guarded by [lock]
    private val lock = Any()
    private var totalChars = 0L
    @Volatile private var ignoreUntil = 0L
    private val loadStarted = AtomicBoolean(false)
    private val persistExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "clipboard-history-persist").apply { isDaemon = true }
    }
    private val persistDirty = AtomicBoolean(false)
    private val persistPending = AtomicBoolean(false)

    private val tokenLike = Regex("^[A-Za-z0-9+/_=:.-]{60,}$")
    private val cardLike = Regex("^[0-9][0-9 -]{11,22}[0-9]$")

    fun preload(context: Context) {
        if (!loadStarted.compareAndSet(false, true)) return
        val app = context.applicationContext
        Thread { loadFromDisk(app) }.apply { isDaemon = true }.start()
    }

    /** Call right before this app writes its own (possibly sensitive) result to the clipboard. */
    fun ignoreNext() { ignoreUntil = System.currentTimeMillis() + 2500L }

    fun count(): Int = synchronized(lock) { items.size }

    fun add(context: Context, raw: String): Boolean {
        if (System.currentTimeMillis() < ignoreUntil) return false
        val text = raw.trim()
        if (text.isEmpty() || text.length > MAX_ITEM_CHARS) return false
        if (text.startsWith("SKF") || text.startsWith("SKFT1:")) return false
        if (!text.any { it.isWhitespace() } && tokenLike.matches(text)) return false
        if (cardLike.matches(text)) return false
        synchronized(lock) {
            val existing = items.indexOfFirst { it.text == text }
            val pinned = if (existing >= 0) items[existing].pinned else false
            if (existing >= 0) {
                totalChars -= items[existing].text.length
                items.removeAt(existing)
            }
            items.add(0, Clip(text, System.currentTimeMillis(), pinned))
            totalChars += text.length
            evictLocked()
        }
        persist(context.applicationContext)
        return true
    }

    private fun evictLocked() {
        var i = items.size - 1
        while ((items.size > MAX_ITEMS || totalChars > MAX_TOTAL_CHARS) && i >= 0) {
            if (!items[i].pinned) {
                totalChars -= items[i].text.length
                items.removeAt(i)
            }
            i--
        }
    }

    /** Pinned first, then newest first; [filter] is a case-insensitive "contains". */
    fun snapshot(filter: String): List<Clip> {
        val f = filter.trim()
        val copy = synchronized(lock) { ArrayList(items) }
        val matched = if (f.isEmpty()) copy else copy.filter { it.text.contains(f, ignoreCase = true) }
        return matched.filter { it.pinned } + matched.filter { !it.pinned }
    }

    fun togglePin(context: Context, clip: Clip) {
        synchronized(lock) { clip.pinned = !clip.pinned }
        persist(context.applicationContext)
    }

    fun remove(context: Context, clip: Clip) {
        synchronized(lock) {
            if (items.remove(clip)) totalChars -= clip.text.length
        }
        persist(context.applicationContext)
    }

    fun clearAll(context: Context) {
        synchronized(lock) { items.clear(); totalChars = 0L }
        val app = context.applicationContext
        persistExecutor.execute {
            try { File(app.filesDir, FILE_NAME).delete() } catch (_: Exception) {}
        }
    }

    private fun loadFromDisk(context: Context) {
        val file = File(context.filesDir, FILE_NAME)
        if (!file.exists()) return
        var encrypted: ByteArray? = null
        var decrypted: ByteArray? = null
        try {
            encrypted = file.readBytes()
            decrypted = LocalStorageCrypto.decrypt(encrypted) ?: return
            val loaded = ArrayList<Clip>()
            var total = 0L
            String(decrypted, Charsets.UTF_8).lineSequence().forEach { line ->
                val p = line.split('\t')
                if (p.size != 3) return@forEach
                val time = p[0].toLongOrNull() ?: return@forEach
                val text = try { String(Base64.decode(p[2], Base64.NO_WRAP), Charsets.UTF_8) } catch (_: Exception) { return@forEach }
                if (text.isEmpty()) return@forEach
                loaded.add(Clip(text, time, p[1] == "1"))
                total += text.length
            }
            synchronized(lock) {
                // Anything captured while loading is newer: keep it in front.
                val fresh = ArrayList(items)
                items.clear(); items.addAll(fresh); items.addAll(loaded)
                totalChars += total
            }
        } catch (_: Exception) {
            // Unreadable storage never crashes the keyboard.
        } finally {
            encrypted?.fill(0); decrypted?.fill(0)
        }
    }

    private fun persist(context: Context) {
        persistDirty.set(true)
        if (!persistPending.compareAndSet(false, true)) return
        persistExecutor.execute {
            try {
                try { Thread.sleep(1500) } catch (_: InterruptedException) {}  // coalesce bursts of copies
                while (persistDirty.compareAndSet(true, false)) {
                    var plain: ByteArray? = null
                    var enc: ByteArray? = null
                    try {
                        val snapshot = synchronized(lock) { ArrayList(items) }
                        val sb = StringBuilder()
                        for (c in snapshot) {
                            sb.append(c.time).append('\t').append(if (c.pinned) '1' else '0').append('\t')
                                .append(Base64.encodeToString(c.text.toByteArray(Charsets.UTF_8), Base64.NO_WRAP))
                                .append('\n')
                        }
                        plain = sb.toString().toByteArray(Charsets.UTF_8)
                        enc = LocalStorageCrypto.encrypt(plain)
                        val target = File(context.filesDir, FILE_NAME)
                        val temp = File(context.filesDir, "$FILE_NAME.tmp")
                        temp.outputStream().use { it.write(enc); it.flush() }
                        if (!temp.renameTo(target)) { temp.delete() }
                    } catch (_: Exception) {
                        // History is optional; never break typing.
                    } finally {
                        plain?.fill(0); enc?.fill(0)
                    }
                }
            } finally {
                persistPending.set(false)
                if (persistDirty.get() && persistPending.compareAndSet(false, true)) persist(context)
            }
        }
    }
}
