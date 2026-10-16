package com.securekeyboard.app

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.BitmapFactory
import android.os.Bundle
import android.provider.DocumentsContract
import android.view.View
import android.view.WindowManager
import android.webkit.MimeTypeMap
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ImageView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.FileProvider
import java.io.File
import java.io.FileInputStream
import java.util.Arrays

/**
 * Secure receive path for .skf files opened from WhatsApp, Files, or the
 * Android Sharesheet. The encrypted file is never copied into the keyboard's
 * clipboard.
 *
 * V43 flow: when a session passphrase is active the file is decrypted automatically
 * (every paired contact is tried unless one was picked), images are previewed inside
 * this FLAG_SECURE screen, and the user can open the file in a viewer or save a copy.
 * The decrypted file lives in the app cache only: purged after [OPEN_FILE_MAX_AGE_MS].
 */
class SecureFileReceiveActivity : Activity() {
    companion object {
        const val EXTRA_INBOX_NAME = "inbox_name"
        private const val PICK_OUTPUT_TREE = 6201
        private const val OPEN_DIR = "secure_open"
        private const val OPEN_FILE_MAX_AGE_MS = 10 * 60 * 1000L
        private val IMAGE_EXTENSIONS = setOf("jpg", "jpeg", "png", "webp", "gif", "bmp")
    }

    private lateinit var contactSpinner: Spinner
    private lateinit var statusText: TextView
    private lateinit var selectedText: TextView
    private lateinit var previewImage: ImageView
    private lateinit var decryptBtn: Button
    private lateinit var openBtn: Button
    private lateinit var saveBtn: Button
    private val names = mutableListOf<String>()
    private var inputUri: android.net.Uri? = null
    private var inboxFile: File? = null
    private var pendingFilename = "decrypted_file"
    private var pendingTempPath: String? = null
    private var openedExternally = false
    @Volatile private var decrypting = false

    override fun onCreate(savedInstanceState: Bundle?) {
        ThemeUtil.applyTo(this)
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_secure_file_receive)
        purgeOldOpenFiles()
        try { SessionKeyStore.initialize(this) } catch (_: Throwable) {}

        contactSpinner = findViewById(R.id.receive_contact_spinner)
        statusText = findViewById(R.id.receive_status)
        selectedText = findViewById(R.id.receive_selected_text)
        previewImage = findViewById(R.id.receive_preview)
        decryptBtn = findViewById(R.id.receive_decrypt_btn)
        openBtn = findViewById(R.id.receive_open_btn)
        saveBtn = findViewById(R.id.receive_save_btn)

        decryptBtn.setOnClickListener { beginDecrypt() }
        openBtn.setOnClickListener { openDecrypted() }
        saveBtn.setOnClickListener { launchOutputPicker() }
        findViewById<Button>(R.id.receive_close_btn).setOnClickListener { finish() }

        // V53: a file that arrived as chat text (SKFT1:) was rebuilt by the keyboard into this app's own
        // inbox; only a plain file NAME is accepted here and it must resolve inside that inbox.
        FileTextTransport.purgeOld(this)
        inboxFile = FileTextTransport.resolveInbox(this, intent.getStringExtra(EXTRA_INBOX_NAME))
        inputUri = inboxFile?.let { android.net.Uri.fromFile(it) }
            ?: SecurityIntentValidator.encryptedFileUri(intent, packageName)
        if (inputUri == null) {
            statusText.text = "رابط أو ملف غير صالح"
            decryptBtn.isEnabled = false
        }
        selectedText.text = queryDisplayName(inputUri) ?: "ملف مشفر"
        refreshContacts()
        refreshSessionStatus()

        // Seamless path: nothing to tap when everything needed is already available.
        if (inputUri != null) beginDecrypt()
    }

    /** Position 0 is "automatic"; positions 1..n are the paired contacts. */
    private fun refreshContacts() {
        names.clear()
        names.addAll(ContactStore.listPairedContactNames(this))
        val labels = if (names.isEmpty()) {
            listOf("تلقائي")
        } else {
            listOf("تلقائي — تجربة كل جهات الاتصال") + names
        }
        contactSpinner.adapter = ArrayAdapter(this, R.layout.spinner_item_light_text, labels).also {
            it.setDropDownViewResource(R.layout.spinner_dropdown_item_light_text)
        }
    }

    private fun refreshSessionStatus() {
        statusText.text = when {
            inputUri == null -> "لم يتم العثور على ملف مشفر"
            else -> "جاهز لفك التشفير بمفتاح هذا الجهاز"
        }
    }

    private fun beginDecrypt() {
        if (decrypting) return
        val uri = inputUri ?: run {
            Toast.makeText(this, "لم يتم العثور على الملف المشفر", Toast.LENGTH_LONG).show()
            return
        }
        // Current (v3) files need only this device's private key. An active
        // session passphrase is used only as a fallback for older files.
        val pass: CharArray? = if (SessionKeyStore.isActive()) SessionKeyStore.get() else null
        val position = contactSpinner.selectedItemPosition
        val candidates: List<String?> = if (position <= 0) {
            listOf<String?>(null) + names.toList()   // null = no contact (v3 path) first
        } else {
            listOf(names.getOrNull(position - 1))
        }

        decrypting = true
        statusText.text = "جارٍ التحقق وفك تشفير الملف…"
        decryptBtn.isEnabled = false
        Thread {
            var opened: File? = null
            var displayName = "decrypted_file"
            var needsSessionKey = false
            try {
                for (name in candidates) {
                    try {
                        val publicKey = if (name == null) null else {
                            val contactB64 = ContactStore.getPairedContact(this, name) ?: continue
                            DeviceIdentity.parseContactPublicKey(contactB64)
                        }
                        val result = SecureFileCrypto.decryptToTemp(this, uri, publicKey, pass)
                        displayName = sanitizeFilename(result.second)
                        opened = moveToOpenDir(result.first, displayName)
                        break
                    } catch (e: Exception) {
                        // Wrong contact, wrong passphrase or damaged file: try the next candidate.
                        if (e is SecureFileCrypto.PassphraseRequiredException) needsSessionKey = true
                    }
                }
            } finally {
                pass?.let { Arrays.fill(it, '\u0000') }
            }
            val decrypted = opened
            if (decrypted == null) {
                runOnUiThread {
                    decrypting = false
                    statusText.text = if (needsSessionKey && pass == null) {
                        "هذا الملف مشفّر بمفتاح الجلسة ولا يوجد مفتاح جلسة نشط الآن. فعّل نفس مفتاح الجلسة من لوحة التشفير ثم اضغط «فك التشفير» هنا."
                    } else {
                        "فشل فك التشفير — لم يُشفَّر لمفتاحك العام، أو مفتاح الجلسة الحالي يختلف عن الذي شُفّر به، أو الملف تالف."
                    }
                    Toast.makeText(this, statusText.text, Toast.LENGTH_LONG).show()
                    decryptBtn.isEnabled = true
                }
            } else {
                val bitmap = decodePreview(decrypted, displayName)
                runOnUiThread {
                    decrypting = false
                    pendingFilename = displayName
                    pendingTempPath = decrypted.absolutePath
                    selectedText.text = displayName
                    statusText.text = "✓ تم فك التشفير والتحقق من الملف"
                    decryptBtn.visibility = View.GONE
                    if (SafeFileTypes.isRisky(displayName)) {
                        openBtn.visibility = View.GONE
                        statusText.text = "✓ تم فك التشفير — ⚠ ملف قابل للتنفيذ أو نشط (${displayName.substringAfterLast('.')}). لن يُفتح من التطبيق؛ لا تشغّله إلا إن كنت واثقًا بمصدره."
                    } else {
                        openBtn.visibility = View.VISIBLE
                    }
                    saveBtn.visibility = View.VISIBLE
                    if (bitmap != null) {
                        previewImage.setImageBitmap(bitmap)
                        previewImage.visibility = View.VISIBLE
                    }
                }
            }
        }.start()
    }

    /** Gives the decrypted file a viewer-friendly name inside the short-lived cache folder. */
    private fun moveToOpenDir(temp: File, safeName: String): File {
        val dir = File(cacheDir, OPEN_DIR)
        dir.mkdirs()
        val ext = safeName.substringAfterLast('.', "").lowercase().filter { it.isLetterOrDigit() }.take(8)
        val dest = File(dir, "f_" + System.nanoTime() + (if (ext.isNotEmpty()) ".$ext" else ""))
        if (!temp.renameTo(dest)) {
            temp.inputStream().use { input -> dest.outputStream().use { output -> input.copyTo(output) } }
            SecureMemory.secureDelete(temp)
        }
        return dest
    }

    private fun decodePreview(file: File, name: String): android.graphics.Bitmap? {
        val ext = name.substringAfterLast('.', "").lowercase()
        if (ext !in IMAGE_EXTENSIONS) return null
        return try {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeFile(file.absolutePath, bounds)
            if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
            var sample = 1
            while (bounds.outWidth / sample > 1600 || bounds.outHeight / sample > 1600) sample *= 2
            BitmapFactory.decodeFile(file.absolutePath, BitmapFactory.Options().apply { inSampleSize = sample })
        } catch (_: Throwable) {
            null
        }
    }

    private fun openDecrypted() {
        val file = pendingTempPath?.let { File(it) }
        if (file == null || !file.exists()) {
            Toast.makeText(this, "انتهت جلسة الملف المؤقتة، أعد فك التشفير", Toast.LENGTH_LONG).show()
            return
        }
        val ext = file.name.substringAfterLast('.', "").lowercase()
        val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
        try {
            val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            val view = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, mime)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            openedExternally = true
            startActivity(view)
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(this, "لا يوجد تطبيق يفتح هذا النوع، استخدم حفظ نسخة", Toast.LENGTH_LONG).show()
        } catch (_: Exception) {
            Toast.makeText(this, "تعذر فتح الملف", Toast.LENGTH_LONG).show()
        }
    }

    private fun launchOutputPicker() {
        val file = pendingTempPath?.let { File(it) }
        if (file == null || !file.exists()) {
            Toast.makeText(this, "انتهت جلسة الملف المؤقتة، أعد فك التشفير", Toast.LENGTH_LONG).show()
            return
        }
        val tree = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
        }
        try {
            @Suppress("DEPRECATION")
            startActivityForResult(tree, PICK_OUTPUT_TREE)
        } catch (e: Exception) {
            statusText.text = "تعذر فتح مدير الملفات"
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != PICK_OUTPUT_TREE) return
        if (resultCode != Activity.RESULT_OK || data?.data == null) {
            statusText.text = "تم إلغاء الحفظ"
            return
        }
        val treeUri = data.data!!
        try {
            contentResolver.takePersistableUriPermission(
                treeUri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        } catch (_: Exception) { }

        val tempFile = pendingTempPath?.let { File(it) }
        if (tempFile == null || !tempFile.exists()) {
            statusText.text = "انتهت جلسة الملف المؤقتة، أعد المحاولة"
            return
        }

        Thread {
            try {
                val parent = DocumentsContract.buildDocumentUriUsingTree(
                    treeUri,
                    DocumentsContract.getTreeDocumentId(treeUri)
                )
                val output = DocumentsContract.createDocument(contentResolver, parent, "*/*", pendingFilename)
                    ?: throw IllegalStateException("cannot create output")
                contentResolver.openOutputStream(output).use { out ->
                    require(out != null) { "cannot open destination" }
                    FileInputStream(tempFile).use { src ->
                        val buffer = ByteArray(64 * 1024)
                        try {
                            while (true) {
                                val n = src.read(buffer)
                                if (n < 0) break
                                out.write(buffer, 0, n)
                            }
                            out.flush()
                        } finally { Arrays.fill(buffer, 0) }
                    }
                }
                runOnUiThread {
                    statusText.text = "✓ تم حفظ الملف بنجاح"
                    Toast.makeText(this, "تم حفظ الملف: $pendingFilename", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                runOnUiThread {
                    statusText.text = "تعذر حفظ الملف في المجلد المحدد"
                    Toast.makeText(this, statusText.text, Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }

    private fun cleanupTemp() {
        pendingTempPath?.let { SecureMemory.secureDelete(File(it)) }
        pendingTempPath = null
    }

    /** Removes decrypted files left in the cache by earlier sessions. */
    private fun purgeOldOpenFiles() {
        try {
            val dir = File(cacheDir, OPEN_DIR)
            val now = System.currentTimeMillis()
            dir.listFiles()?.forEach { f ->
                if (now - f.lastModified() > OPEN_FILE_MAX_AGE_MS) SecureMemory.secureDelete(f)
            }
        } catch (_: Exception) { }
    }

    override fun onDestroy() {
        previewImage.setImageDrawable(null)
        // If a viewer app was launched, leave the file for it; the age-based purge removes it later.
        if (!openedExternally) cleanupTemp()
        if (isFinishing) inboxFile?.delete()
        super.onDestroy()
    }

    private fun queryDisplayName(uri: android.net.Uri?): String? {
        if (uri == null || uri.scheme != "content") return null
        contentResolver.query(uri, arrayOf("_display_name"), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val i = c.getColumnIndex("_display_name")
                if (i >= 0) return c.getString(i)
            }
        }
        return null
    }

    private fun sanitizeFilename(value: String): String {
        val cleaned = value.replace(Regex("[\\\\/:*?\"<>|]"), "_").trim()
        return if (cleaned.isBlank()) "decrypted_file" else cleaned.take(180)
    }
}
