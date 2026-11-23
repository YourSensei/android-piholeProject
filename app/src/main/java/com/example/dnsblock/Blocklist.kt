package com.example.dnsblock

import android.content.Context
import java.io.File
import java.net.URL

object Blocklist {
    const val URL_DEFAULT = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    @Volatile private var domains: Set<String> = emptySet()
    @Volatile private var allow: Set<String> = emptySet()   // user allowlist (wins over everything)
    @Volatile private var deny: Set<String> = emptySet()    // user blocklist

    val size get() = domains.size
    private fun sp(c: Context) = c.getSharedPreferences("cfg", Context.MODE_PRIVATE)

    fun load(ctx: Context) {
        val f = File(ctx.filesDir, "blocklist.txt")
        val text = if (f.exists()) f.readText() else ctx.assets.open("hosts.txt").bufferedReader().readText()
        val set = HashSet<String>()
        for (raw in text.lineSequence()) {
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue
            val parts = line.split(Regex("\\s+"))
            val d = (if (parts.size >= 2) parts[1] else parts[0]).lowercase()
            if (d != "localhost" && d != "0.0.0.0" && d.contains('.')) set.add(d)
        }
        domains = set
        allow = sp(ctx).getStringSet("allow", emptySet())!!.toSet()
        deny = sp(ctx).getStringSet("deny", emptySet())!!.toSet()
    }

    private fun matches(s: Set<String>, name: String): Boolean {
        var n = name.lowercase().trimEnd('.')
        while (true) {
            if (n in s) return true
            val i = n.indexOf('.')
            if (i < 0) return false
            n = n.substring(i + 1)
        }
    }

    fun isBlocked(name: String): Boolean =
        if (matches(allow, name)) false else matches(deny, name) || matches(domains, name)

    /** Called when the user taps a domain: block = true -> block it, false -> allow it. */
    fun setRule(ctx: Context, domain: String, block: Boolean) {
        val d = domain.lowercase().trimEnd('.')
        val a = allow.toMutableSet(); val b = deny.toMutableSet()
        if (block) { a.remove(d); b.add(d) } else { b.remove(d); a.add(d) }
        allow = a; deny = b
        sp(ctx).edit().putStringSet("allow", HashSet(a)).putStringSet("deny", HashSet(b)).apply()
    }

    fun lastUpdated(ctx: Context): Long = sp(ctx).getLong("updated", 0L)

    fun update(ctx: Context): Boolean = try {
        val text = URL(URL_DEFAULT).openStream().bufferedReader().readText()
        if (text.length < 10_000) throw IllegalStateException("list too small")
        val tmp = File(ctx.filesDir, "blocklist.tmp")
        tmp.writeText(text)
        tmp.renameTo(File(ctx.filesDir, "blocklist.txt"))
        load(ctx)
        sp(ctx).edit().putLong("updated", System.currentTimeMillis()).apply()
        true
    } catch (e: Exception) { false }
}
