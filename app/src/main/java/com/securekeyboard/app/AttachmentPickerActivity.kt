package com.securekeyboard.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.Toast

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
        // Persisted first (commit): the keyboard process may have been killed while the
        // file manager was in the foreground, so a live broadcast alone could be lost.
        Prefs.setPendingAttachment(this, uri.toString(), name)
        done(notifyKeyboard = true)
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
