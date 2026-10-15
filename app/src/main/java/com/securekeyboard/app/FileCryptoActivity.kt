package com.securekeyboard.app

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.webkit.MimeTypeMap
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import com.google.android.material.button.MaterialButton
import java.io.File
import java.io.FileInputStream
import java.util.Arrays

/**
 * File encryption screen (opened from the keyboard's "📁 تشفير الملفات" button).
 *
 * Flow - one screen, no second file manager:
 *   1. choose a contact (REQUIRED for encryption - the file is sealed with that
 *      contact's PUBLIC key; only their device can open it),
 *   2. press "اختيار ملف" (the only time the system file picker opens),
 *   3. press "تشفير" -> the encrypted .skf is written to the app's private
 *      outbox right away and can be shared or saved with the buttons below.
 * Decryption needs no contact: current files are opened with this device's
 * own private key. No session passphrase is required any more.
 */
class FileCryptoActivity : AppCompatActivity() {
    private lateinit var contactSpinner: Spinner
    private lateinit var selectedFileText: TextView
    private lateinit var statusText: TextView
    private lateinit var encryptBtn: MaterialButton
    private lateinit var decryptBtn: MaterialButton
    private lateinit var shareBtn: MaterialButton
    private lateinit var saveBtn: MaterialButton
    private lateinit var openBtn: MaterialButton

    private var selectedInputUri: Uri? = null
    private var selectedDisplayName: String = ""
    private var resultFile: File? = null
    private var resultName: String = ""
    private var resultIsEncrypted = true
    @Volatile private var busy = false
    private val names = mutableListOf<String>()

    companion object {
        const val EXTRA_CONTACT_NAME = "contact_name"
        private const val PICK_INPUT = 5101
        private const val ADD_CONTACT = 5103
        private const val SAVE_RESULT = 5105
        private const val STATE_URI = "state_uri"
        private const val STATE_NAME = "state_name"
        private const val OUTBOX = "secure_outbox"
        private const val OPEN_DIR = "secure_open"
        private const val MAX_AGE_MS = 6L * 60L * 60L * 1000L
        const val SELF_LABEL = "🔒 نفسي (هذا الجهاز فقط)"
        private const val PLACEHOLDER = "— اختر جهة اتصال —"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        ThemeUtil.applyTo(this)
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_file_crypto)

        contactSpinner = findViewById(R.id.file_contact_spinner)
        selectedFileText = findViewById(R.id.file_selected_text)
        statusText = findViewById(R.id.file_status)
        encryptBtn = findViewById(R.id.file_pick_encrypt)
        decryptBtn = findViewById(R.id.file_pick_decrypt)
        shareBtn = findViewById(R.id.file_share)
        saveBtn = findViewById(R.id.file_save)
        openBtn = findViewById(R.id.file_open)

        savedInstanceState?.let {
            selectedInputUri = it.getString(STATE_URI)?.let { s -> Uri.parse(s) }
            selectedDisplayName = it.getString(STATE_NAME).orEmpty()
        }

        findViewById<MaterialButton>(R.id.file_add_contact).setOnClickListener {
            @Suppress("DEPRECATION")
            startActivityForResult(Intent(this, ContactPairingActivity::class.java), ADD_CONTACT)
        }
        findViewById<MaterialButton>(R.id.file_choose).setOnClickListener { pickFile() }
        encryptBtn.setOnClickListener { startOperation(encrypt = true) }
        decryptBtn.setOnClickListener { startOperation(encrypt = false) }
        shareBtn.setOnClickListener { shareResult() }
        saveBtn.setOnClickListener { saveResultAs() }
        openBtn.setOnClickListener { openResult() }

        refreshContacts(intent.getStringExtra(EXTRA_CONTACT_NAME))
        refreshFileLabel()
        statusText.text = "1) اختر جهة الاتصال  2) اختر الملف  3) اضغط تشفير"
        ThemeUtil.tintPrimary(this, encryptBtn, findViewById(R.id.file_choose))
        ThemeUtil.tintOutline(this, findViewById(R.id.file_add_contact), decryptBtn, shareBtn, saveBtn, openBtn)
        Fonts.applyToTree(findViewById(android.R.id.content), Fonts.currentTypeface(this))
        purgeOldFiles()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(STATE_URI, selectedInputUri?.toString())
        outState.putString(STATE_NAME, selectedDisplayName)
    }

    /** Spinner: [placeholder] + contacts + [self]. Keeps the current choice across refreshes. */
    private fun refreshContacts(preferred: String? = null) {
        val previous = preferred ?: (contactSpinner.selectedItem as? String)
        names.clear()
        names.addAll(ContactStore.listPairedContactNames(this))
        val labels = listOf(PLACEHOLDER) + names + listOf(SELF_LABEL)
        contactSpinner.adapter = ArrayAdapter(this, R.layout.spinner_item_light_text, labels).also {
            it.setDropDownViewResource(R.layout.spinner_dropdown_item_light_text)
        }
        val idx = if (previous == null) -1 else labels.indexOf(previous)
        if (idx > 0) contactSpinner.setSelection(idx)
    }

    private fun refreshFileLabel() {
        selectedFileText.text = if (selectedInputUri == null) getString(R.string.file_none_selected) else "📄 $selectedDisplayName"
    }

    @Suppress("DEPRECATION")
    private fun pickFile() {
        if (busy) return
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        try {
            startActivityForResult(intent, PICK_INPUT)
        } catch (e: Exception) {
            say("تعذر فتح مدير الملفات: ${e.message ?: "غير مدعوم"}")
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            ADD_CONTACT -> refreshContacts()
            PICK_INPUT -> {
                val uri = if (resultCode == Activity.RESULT_OK) data?.data else null
                if (uri != null) {
                    try { contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) } catch (_: Exception) {}
                    selectedInputUri = uri
                    selectedDisplayName = queryDisplayName(uri) ?: "file"
                    clearResult()
                    refreshFileLabel()
                    say("تم اختيار الملف. اضغط «تشفير» أو «فك تشفير».")
                }
            }
            SAVE_RESULT -> {
                val dest = if (resultCode == Activity.RESULT_OK) data?.data else null
                if (dest != null) copyResultTo(dest)
            }
        }
    }

    /** Public key of the chosen target, or null (with a message) when none is chosen. */
    private fun selectedPublicKeyB64(): Pair<String, String>? {
        val pos = contactSpinner.selectedItemPosition
        val label = contactSpinner.selectedItem as? String
        if (pos <= 0 || label == null) return null
        if (label == SELF_LABEL) return SELF_LABEL to DeviceIdentity.myPublicKeyBase64(this)
        val b64 = ContactStore.getPairedContact(this, label) ?: return null
        return label to b64
    }

    private fun startOperation(encrypt: Boolean) {
        if (busy) return
        val input = selectedInputUri
        if (input == null) {
            say("اضغط «اختيار ملف» أولًا.")
            return
        }
        val target: Pair<String, String>? = if (encrypt) selectedPublicKeyB64() else null
        if (encrypt) {
            if (target == null) {
                say("اختر جهة اتصال أولًا — سيُشفَّر الملف بمفتاحها العام. أضف جهة من الزر أعلاه إن لم تكن موجودة.")
                return
            }
        }
        busy = true
        clearResult()
        setButtonsEnabled(false)
        say(if (encrypt) "جارٍ التشفير بالمفتاح العام… لا تغلق الشاشة" else "جارٍ فك التشفير… لا تغلق الشاشة")
        val displayName = selectedDisplayName.ifBlank { "file" }
        // Old (v1/v2) files may still need the session passphrase / a contact key.
        val legacyContactKey = if (!encrypt) selectedPublicKeyB64()?.second else null
        val pass = if (!encrypt && SessionKeyStore.isActive()) SessionKeyStore.get() else null
        Thread {
            try {
                if (encrypt) {
                    val key = DeviceIdentity.parseContactPublicKey(target!!.second)
                    val dir = File(filesDir, OUTBOX).apply { mkdirs() }
                    val outName = sanitize(displayName) + ".skf"
                    val outFile = File(dir, "enc_${System.currentTimeMillis()}.skf")
                    SecureFileCrypto.encryptToFile(this, input, outFile, key, displayName)
                    onDone(outFile, outName, true, "✓ تم تشفير الملف للجهة «${target!!.first}» بمفتاحها العام")
                } else {
                    val contactKey = legacyContactKey?.let { runCatching { DeviceIdentity.parseContactPublicKey(it) }.getOrNull() }
                    val (temp, filename) = SecureFileCrypto.decryptToTemp(this, input, contactKey, pass)
                    val dir = File(cacheDir, OPEN_DIR).apply { mkdirs() }
                    val safe = sanitize(filename)
                    val ext = safe.substringAfterLast('.', "").lowercase().filter { it.isLetterOrDigit() }.take(8)
                    val dest = File(dir, "f_" + System.nanoTime() + if (ext.isNotEmpty()) ".$ext" else "")
                    if (!temp.renameTo(dest)) {
                        temp.inputStream().use { i -> dest.outputStream().use { o -> i.copyTo(o) } }
                        SecureMemory.secureDelete(temp)
                    }
                    onDone(dest, safe, false, "✓ تم فك التشفير — الملف: $safe")
                }
            } catch (e: Exception) {
                val msg = when {
                    e is SecureFileCrypto.PassphraseRequiredException ->
                        "هذا ملف بصيغة قديمة يحتاج مفتاح جلسة نشطًا (فعّله من شاشة التشفير) واختيار جهة الاتصال."
                    e is javax.crypto.AEADBadTagException || e.cause is javax.crypto.AEADBadTagException ->
                        if (encrypt) "فشل التشفير: ${e.message}"
                        else "لا يمكن فك هذا الملف على هذا الجهاز: لم يُشفَّر لمفتاحك العام (أو الملف تالف)."
                    e.message?.contains("not a SecureKeyboard file") == true ->
                        "هذا ليس ملفًا مشفّرًا بواسطة هذا التطبيق (لاحقة .skf)."
                    else -> "تعذر تنفيذ العملية: ${e.message ?: "خطأ غير معروف"}"
                }
                runOnUiThread { busy = false; setButtonsEnabled(true); say(msg, toast = true) }
            } finally {
                pass?.let { Arrays.fill(it, '\u0000') }
            }
        }.start()
    }

    private fun onDone(file: File, name: String, encrypted: Boolean, message: String) {
        runOnUiThread {
            busy = false
            resultFile = file
            resultName = name
            resultIsEncrypted = encrypted
            setButtonsEnabled(true)
            shareBtn.visibility = View.VISIBLE
            saveBtn.visibility = View.VISIBLE
            val risky = !encrypted && SafeFileTypes.isRisky(name)
            openBtn.visibility = if (encrypted || risky) View.GONE else View.VISIBLE
            say(if (risky) "$message\n⚠ ملف قابل للتنفيذ أو نشط: لن يُفتح من التطبيق، ولا تشغّله إلا إن كنت واثقًا بمصدره." else message, toast = true)
        }
    }

    private fun clearResult() {
        resultFile?.let { f -> if (!resultIsEncrypted) SecureMemory.secureDelete(f) }
        resultFile = null
        shareBtn.visibility = View.GONE
        saveBtn.visibility = View.GONE
        openBtn.visibility = View.GONE
    }

    private fun shareResult() {
        val file = resultFile?.takeIf { it.exists() } ?: return say("انتهت صلاحية الملف المؤقت، أعد العملية.")
        try {
            val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            val send = Intent(Intent.ACTION_SEND).apply {
                type = if (resultIsEncrypted) "application/octet-stream" else (mimeFor(resultName))
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_TITLE, resultName)
                clipData = android.content.ClipData.newRawUri(resultName, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(send, "مشاركة الملف"))
        } catch (e: Exception) {
            say("تعذر فتح المشاركة: ${e.message ?: "خطأ"}")
        }
    }

    @Suppress("DEPRECATION")
    private fun saveResultAs() {
        resultFile?.takeIf { it.exists() } ?: return say("انتهت صلاحية الملف المؤقت، أعد العملية.")
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = if (resultIsEncrypted) "application/octet-stream" else mimeFor(resultName)
            putExtra(Intent.EXTRA_TITLE, resultName)
        }
        try { startActivityForResult(intent, SAVE_RESULT) } catch (e: Exception) { say("تعذر فتح مدير الملفات: ${e.message ?: ""}") }
    }

    private fun copyResultTo(dest: Uri) {
        val file = resultFile?.takeIf { it.exists() } ?: return say("انتهت صلاحية الملف المؤقت، أعد العملية.")
        Thread {
            try {
                contentResolver.openOutputStream(dest, "wt").use { out ->
                    require(out != null) { "cannot open destination" }
                    FileInputStream(file).use { it.copyTo(out, 64 * 1024) }
                    out.flush()
                }
                runOnUiThread { say("✓ تم حفظ الملف", toast = true) }
            } catch (e: Exception) {
                runOnUiThread { say("تعذر حفظ الملف: ${e.message ?: "خطأ"}", toast = true) }
            }
        }.start()
    }

    private fun openResult() {
        val file = resultFile?.takeIf { it.exists() } ?: return say("انتهت صلاحية الملف المؤقت، أعد العملية.")
        try {
            val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
            startActivity(Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, mimeFor(resultName))
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            })
        } catch (_: ActivityNotFoundException) {
            say("لا يوجد تطبيق يفتح هذا النوع — استخدم «حفظ» أو «مشاركة».")
        } catch (e: Exception) {
            say("تعذر فتح الملف: ${e.message ?: ""}")
        }
    }

    private fun mimeFor(name: String): String {
        val ext = name.substringAfterLast('.', "").lowercase()
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
    }

    private fun setButtonsEnabled(on: Boolean) {
        encryptBtn.isEnabled = on
        decryptBtn.isEnabled = on
        findViewById<MaterialButton>(R.id.file_choose).isEnabled = on
    }

    private fun say(text: String, toast: Boolean = false) {
        statusText.text = text
        if (toast) Toast.makeText(this, text, Toast.LENGTH_LONG).show()
    }

    private fun purgeOldFiles() {
        val now = System.currentTimeMillis()
        listOf(File(filesDir, OUTBOX), File(cacheDir, OPEN_DIR)).forEach { dir ->
            try {
                dir.listFiles()?.forEach { f -> if (now - f.lastModified() > MAX_AGE_MS) SecureMemory.secureDelete(f) }
            } catch (_: Exception) {}
        }
    }

    override fun onDestroy() {
        if (!isChangingConfigurations) resultFile?.let { if (!resultIsEncrypted) SecureMemory.secureDelete(it) }
        super.onDestroy()
    }

    private fun sanitize(value: String): String {
        val n = value.replace('\\', '_').replace('/', '_').replace(Regex("[\\u0000-\\u001F\\u007F]"), "_").trim()
        val safe = n.trim('.', ' ')
        return when {
            safe.isBlank() -> "file"
            safe.length > 160 -> safe.take(160)
            else -> safe
        }
    }

    private fun queryDisplayName(uri: Uri): String? {
        return try {
            contentResolver.query(uri, arrayOf("_display_name"), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            }
        } catch (_: Exception) { null }
    }
}
