package com.securekeyboard.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.Toast
import java.io.File
import java.security.SecureRandom

/**
 * The 📎 button of the keyboard's secure-compose page.
 *
 * Flow (same idea as typing a message):
 *   1. 📎  -> this (transparent) Activity opens the system file manager once.
 *   2. The chosen file is only REMEMBERED (uri + name, nothing is read or encrypted here)
 *      and the Activity closes, so the user lands back on the secure-compose keyboard
 *      with the file shown in the secure box, exactly like typed text.
 *   3. 🔐 in the keyboard then encrypts it - for the selected contact (public-key,
 *      SKF2 v3) or, when no contact is selected, in public/session mode (SKF2 v4) -
 *      and injects the encrypted copy into the chat.
 * The original file is only read, never modified or deleted.
 */
class AttachmentPickerActivity : Activity() {
    companion object {
        const val ACTION_ATTACHMENT_SELECTED = "com.securekeyboard.app.ATTACHMENT_SELECTED"
        const val EXTRA_URI = "uri"
        const val EXTRA_NAME = "name"
        const val EXTRA_MIME = "mime"
        // Kept so older callers that still pass the selected contact keep compiling; unused here.
        const val EXTRA_CONTACT = "contact"
        private const val PICK = 7401
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Recreated while the picker is open (rotation, process death): the result
        // is still delivered to onActivityResult, nothing to restart.
        if (savedInstanceState != null) return
        openPicker()
    }

    @Suppress("DEPRECATION")
    private fun openPicker() {
        try {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
            }, PICK)
        } catch (e: Exception) {
            Toast.makeText(this, "تعذر فتح مدير الملفات", Toast.LENGTH_LONG).show()
            done()
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != PICK) return
        val uri = if (resultCode == RESULT_OK) data?.data else null
        if (uri == null) {
            done()
            return
        }
        try {
            contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } catch (_: Exception) {
            // Not every provider offers a persistable grant; the temporary one is enough
            // while this app's process is alive.
        }
        val name = queryName(uri)
        // V54: many file managers (e.g. Ace File Explorer) hand out a TEMPORARY read grant that dies as
        // soon as this Activity finishes ("Permission Denial: opening provider ... that is not exported").
        // Read the file NOW, while the grant is alive, into a private read-only working copy; the
        // keyboard encrypts that copy later and deletes it right after. The original is never touched.
        Toast.makeText(this, "جارٍ تجهيز الملف…", Toast.LENGTH_SHORT).show()
        Thread {
            AttachmentStore.purgeOld(this)
            val copy = AttachmentStore.copyFrom(this, uri)
            runOnUiThread {
                if (copy == null) {
                    Toast.makeText(this, "تعذّر قراءة الملف من مدير الملفات — جرّب اختياره من تطبيق «الملفات» أو مدير آخر", Toast.LENGTH_LONG).show()
                }
                val finalUri = if (copy != null) Uri.fromFile(copy) else uri
                // Persisted first (commit): the keyboard process may have been killed while the
                // file manager was in the foreground, so a live broadcast alone could be lost.
                Prefs.setPendingAttachment(this, finalUri.toString(), name)
                done(notifyKeyboard = true)
            }
        }.start()
    }

    private fun done(notifyKeyboard: Boolean = false) {
        // Lets the keyboard re-show itself when the chat regains focus.
        Prefs.markPickerReturned(this)
        if (notifyKeyboard) {
            try {
                sendBroadcast(Intent(ACTION_ATTACHMENT_SELECTED).setPackage(packageName))
            } catch (_: Exception) {}
        }
        finish()
    }

    private fun queryName(uri: Uri): String {
        try {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) return c.getString(0).orEmpty().ifBlank { "file" }
            }
        } catch (_: Exception) {}
        return uri.lastPathSegment?.substringAfterLast('/')?.ifBlank { "file" } ?: "file"
    }
}

/** V54: private, short-lived working copies of picked files (see AttachmentPickerActivity). */
object AttachmentStore {
    private const val DIR = "secure_attach"
    private const val MAX_AGE_MS = 60L * 60L * 1000L

    private fun dir(c: Context): File = File(c.filesDir, DIR).apply { mkdirs() }

    fun purgeOld(c: Context) {
        val now = System.currentTimeMillis()
        dir(c).listFiles()?.forEach { if (now - it.lastModified() > MAX_AGE_MS) it.delete() }
    }

    /** Streams [uri] into the private dir. Returns null when it cannot be read. */
    fun copyFrom(c: Context, uri: Uri): File? {
        val rnd = ByteArray(8).also { SecureRandom().nextBytes(it) }
        val out = File(dir(c), "att_" + rnd.joinToString("") { "%02x".format(it) } + ".bin")
        return try {
            val input = c.contentResolver.openInputStream(uri) ?: return null
            input.use { i -> out.outputStream().use { o -> i.copyTo(o, 64 * 1024) } }
            out
        } catch (e: Exception) {
            out.delete()
            null
        }
    }

    fun isOwnCopy(c: Context, uri: Uri?): Boolean {
        if (uri == null || uri.scheme != "file") return false
        return try {
            File(uri.path ?: return false).canonicalFile.parentFile == dir(c).canonicalFile
        } catch (e: Exception) { false }
    }

    fun deleteIfOwnCopy(c: Context, uri: Uri?) {
        if (isOwnCopy(c, uri)) try { File(uri!!.path!!).delete() } catch (_: Exception) {}
    }
}
