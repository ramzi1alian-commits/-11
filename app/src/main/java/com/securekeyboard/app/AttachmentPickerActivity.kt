package com.securekeyboard.app

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.core.content.FileProvider
import java.io.File

/**
 * The 📎 button of the keyboard's secure-compose page.
 *
 * Everything happens in this (briefly visible, transparent) Activity instead of
 * depending on the keyboard staying alive while the system file picker is open:
 *   1. contact  - the one selected in the keyboard, otherwise a chooser dialog
 *   2. file     - system file picker (once)
 *   3. encrypt  - with the contact's PUBLIC key, written to the private outbox
 *   4. share    - system share sheet with the encrypted .skf (choose WhatsApp etc.)
 * The original file is only read, never modified.
 */
class AttachmentPickerActivity : Activity() {
    companion object {
        // Kept for the keyboard's receiver (older flow); no longer sent by this screen.
        const val ACTION_ATTACHMENT_SELECTED = "com.securekeyboard.app.ATTACHMENT_SELECTED"
        const val EXTRA_URI = "uri"
        const val EXTRA_NAME = "name"
        const val EXTRA_MIME = "mime"
        const val EXTRA_CONTACT = "contact"
        private const val PICK = 7401
        private const val PAIR = 7402
        private const val STATE_CONTACT = "state_contact"
    }

    private var contact: String? = null
    @Volatile private var working = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        contact = savedInstanceState?.getString(STATE_CONTACT) ?: intent?.getStringExtra(EXTRA_CONTACT)
        if (savedInstanceState != null) return // dialog / picker already in progress
        if (contact.isNullOrBlank() || ContactStore.getPairedContact(this, contact!!) == null) {
            chooseContact()
        } else {
            openPicker()
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(STATE_CONTACT, contact)
    }

    private fun chooseContact() {
        val names = ContactStore.listPairedContactNames(this)
        if (names.isEmpty()) {
            Toast.makeText(this, "أضف جهة اتصال آمنة أولًا لتشفير الملف بمفتاحها العام", Toast.LENGTH_LONG).show()
            @Suppress("DEPRECATION")
            startActivityForResult(Intent(this, ContactPairingActivity::class.java), PAIR)
            return
        }
        AlertDialog.Builder(this)
            .setTitle("شفّر الملف لمن؟")
            .setItems(names.toTypedArray()) { _, which ->
                contact = names[which]
                openPicker()
            }
            .setOnCancelListener { done() }
            .show()
    }

    @Suppress("DEPRECATION")
    private fun openPicker() {
        try {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }, PICK)
        } catch (e: Exception) {
            Toast.makeText(this, "تعذر فتح مدير الملفات", Toast.LENGTH_LONG).show()
            done()
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            PAIR -> done()
            PICK -> {
                val uri = if (resultCode == RESULT_OK) data?.data else null
                if (uri == null) done() else encryptAndShare(uri)
            }
        }
    }

    private fun encryptAndShare(input: Uri) {
        val name = queryName(input)
        val contactName = contact
        val keyB64 = contactName?.let { ContactStore.getPairedContact(this, it) }
        if (keyB64.isNullOrBlank()) {
            Toast.makeText(this, "مفتاح جهة الاتصال غير موجود", Toast.LENGTH_LONG).show()
            done(); return
        }
        val publicKey = try { DeviceIdentity.parseContactPublicKey(keyB64) } catch (e: Exception) {
            Toast.makeText(this, "مفتاح جهة الاتصال غير صالح", Toast.LENGTH_LONG).show()
            done(); return
        }
        working = true
        Toast.makeText(this, "جارٍ تشفير «$name» للجهة $contactName…", Toast.LENGTH_SHORT).show()
        Thread {
            var out: File? = null
            try {
                val dir = File(filesDir, "secure_outbox").apply { mkdirs() }
                val f = File(dir, "out_${System.currentTimeMillis()}.skf")
                out = f
                SecureFileCrypto.encryptToFile(this, input, f, publicKey, name)
                runOnUiThread { share(f, name) }
            } catch (e: Exception) {
                out?.delete()
                runOnUiThread {
                    Toast.makeText(this, "فشل تشفير الملف: ${e.message ?: "خطأ غير معروف"}", Toast.LENGTH_LONG).show()
                    done()
                }
            }
        }.start()
    }

    private fun share(file: File, originalName: String) {
        try {
            val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_TITLE, "$originalName.skf")
                clipData = ClipData.newRawUri("SecureKeyboard encrypted file", uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(send, "إرسال الملف المشفّر — اختر واتساب أو غيره"))
        } catch (e: Exception) {
            Toast.makeText(this, "تم التشفير لكن تعذر فتح المشاركة: ${e.message ?: ""}", Toast.LENGTH_LONG).show()
        }
        done()
    }

    private fun done() {
        working = false
        // Lets the keyboard re-show itself when the chat regains focus.
        Prefs.markPickerReturned(this)
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
