package com.securekeyboard.app

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * EnglishDictionary (V57)
 *
 * English twin of [WordDictionary]: a fixed, read-only, offline word list bundled in the APK
 * (assets/en_words.tsv, one "word<TAB>score" per line, score 1-255, highest first) that serves
 * prefix suggestions while the user types a Latin-letter word. Nothing the user types is added
 * to it or stored by it. Replace the asset with a better frequency list at any time
 * (see tools/make_en_words.py); no code change is needed.
 */
object EnglishDictionary {

    private const val ASSET_NAME = "en_words.tsv"
    private const val MAX_SUGGESTIONS = 5

    @Volatile private var buckets: Map<Char, List<String>>? = null
    @Volatile private var loading = false

    fun preload(context: Context) {
        if (buckets != null || loading) return
        loading = true
        Thread {
            buckets = loadFromAssets(context.applicationContext)
            loading = false
        }.apply { isDaemon = true }.start()
    }

    private fun loadFromAssets(context: Context): Map<Char, List<String>> {
        val grouped = LinkedHashMap<Char, MutableList<String>>()
        try {
            context.assets.open(ASSET_NAME).use { input ->
                BufferedReader(InputStreamReader(input, Charsets.UTF_8)).use { reader ->
                    reader.forEachLine { line ->
                        val tab = line.indexOf('\t')
                        val word = (if (tab > 0) line.substring(0, tab) else line).trim()
                        if (word.isEmpty()) return@forEachLine
                        grouped.getOrPut(word[0]) { mutableListOf() }.add(word)
                    }
                }
            }
        } catch (e: Exception) {
            return emptyMap() // fail quiet: typing never depends on suggestions
        }
        return grouped
    }

    /** True when [prefix] starts with an ASCII letter, i.e. it is an English word being typed. */
    fun isLatinPrefix(prefix: String): Boolean =
        prefix.isNotEmpty() && (prefix[0] in 'a'..'z' || prefix[0] in 'A'..'Z')

    /** Up to [MAX_SUGGESTIONS] completions of [prefix], matching its capitalisation (Hel -> Help, HEL -> HELP). */
    fun suggestionsFor(prefix: String): List<String> {
        if (!isLatinPrefix(prefix)) return emptyList()
        val map = buckets ?: return emptyList()
        val lower = prefix.lowercase()
        val bucket = map[lower[0]] ?: return emptyList()
        val allUpper = prefix.length > 1 && prefix.all { it.isUpperCase() }
        val capital = prefix[0].isUpperCase()
        val out = ArrayList<String>(MAX_SUGGESTIONS)
        for (w in bucket) {
            if (w.length > lower.length && w.startsWith(lower)) {
                out.add(
                    when {
                        allUpper -> w.uppercase()
                        capital -> w.replaceFirstChar { it.uppercase() }
                        else -> w
                    }
                )
                if (out.size >= MAX_SUGGESTIONS) break
            }
        }
        return out
    }
}
