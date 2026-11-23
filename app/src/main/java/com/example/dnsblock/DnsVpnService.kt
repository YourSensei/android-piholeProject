package com.example.dnsblock

import android.app.*
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.HttpsURLConnection

class DnsVpnService : VpnService() {
    companion object {
        const val ACTION_STOP = "stop"
        const val DNS4 = "10.111.222.2"
        const val DNS6 = "fd00:dead:beef::2"
        /** Plain IP ("1.1.1.1", Pi-hole...) or DoH URL with an IP literal ("https://1.1.1.1/dns-query"). */
        @Volatile var upstream = "https://1.1.1.1/dns-query"
        /** If true and DoH fails, retry over plain DNS to the same provider IP (less private). */
        @Volatile var fallback = false
        @Volatile private var dohDownUntil = 0L
        @Volatile var running = false
        val blocked = AtomicInteger()
        val allowed = AtomicInteger()
        val cacheHits = AtomicInteger()
    }

    private class Cached(val data: ByteArray, val exp: Long)
    private val cache = ConcurrentHashMap<String, Cached>()
    private var tun: ParcelFileDescriptor? = null
    private val pool = Executors.newCachedThreadPool()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stopVpn(); return START_NOT_STICKY }
        startForeground(1, notification())
        startVpn()
        return START_STICKY
    }

    private fun notification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("dns", "DNS Blocker", NotificationManager.IMPORTANCE_LOW))
        val stop = PendingIntent.getService(this, 0, Intent(this, DnsVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE)
        val open = PendingIntent.getActivity(this, 1, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val act = Notification.Action.Builder(Icon.createWithResource(this, android.R.drawable.ic_menu_close_clear_cancel), "Stop", stop).build()
        return Notification.Builder(this, "dns")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("DNS Blocker active")
            .setContentText("Ads and trackers are blocked on this device")
            .setContentIntent(open).addAction(act).setOngoing(true).build()
    }

    private fun startVpn() {
        if (running) return
        upstream = getSharedPreferences("cfg", MODE_PRIVATE).getString("upstream", upstream) ?: upstream
        fallback = getSharedPreferences("cfg", MODE_PRIVATE).getBoolean("fallback", false)
        Blocklist.load(this)
        cache.clear()
        tun = Builder()
            .setSession("DNS Blocker")
            .addAddress("10.111.222.1", 32).addAddress("fd00:dead:beef::1", 128)
            .addDnsServer(DNS4).addDnsServer(DNS6)
            .addRoute(DNS4, 32).addRoute(DNS6, 128)
            .setBlocking(true)
            .establish() ?: run { stopSelf(); return }
        running = true
        val fd = tun!!
        Thread { loop(fd) }.start()
    }

    private fun stopVpn() {
        running = false
        tun?.close(); tun = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() { running = false; tun?.close(); super.onDestroy() }
    override fun onRevoke() { stopVpn() }

    private fun loop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        try {
            while (running) {
                val n = input.read(buf)
                if (n <= 0) continue
                handle(buf.copyOf(n), output)
            }
        } catch (_: Exception) { }
    }

    private fun handle(p: ByteArray, out: FileOutputStream) {
        val ver = (p[0].toInt() shr 4)
        val ihl: Int; val aLen: Int; val srcOff: Int
        if (ver == 4) {
            if (p.size < 28) return
            ihl = (p[0].toInt() and 0xF) * 4; aLen = 4; srcOff = 12
            if (p[9].toInt() != 17) return
        } else if (ver == 6) {
            if (p.size < 48) return
            ihl = 40; aLen = 16; srcOff = 8
            if (p[6].toInt() != 17) return
        } else return
        if (p.size < ihl + 8 || u16(p, ihl + 2) != 53) return
        val dns = p.copyOfRange(ihl + 8, p.size)
        val (name, qEnd, qType) = parseQuestion(dns) ?: return
        val src = p.copyOfRange(srcOff, srcOff + aLen)
        val dst = p.copyOfRange(srcOff + aLen, srcOff + 2 * aLen)
        val sport = u16(p, ihl)

        if (Blocklist.isBlocked(name)) {
            blocked.incrementAndGet(); QueryLog.add(name, true)
            reply(out, ver, dst, src, sport, blockedAnswer(dns, qEnd, qType))
            return
        }
        allowed.incrementAndGet(); QueryLog.add(name, false)

        val key = name.lowercase() + "/" + qType
        val hit = cache[key]
        if (hit != null && hit.exp > System.currentTimeMillis()) {
            cacheHits.incrementAndGet()
            val r = hit.data.copyOf(); r[0] = dns[0]; r[1] = dns[1]   // answer carries the new query's ID
            reply(out, ver, dst, src, sport, r)
            return
        }
        pool.execute {
            try {
                val resp = forward(dns)
                ttlOf(resp)?.let {
                    if (cache.size > 2000) cache.clear()
                    cache[key] = Cached(resp, System.currentTimeMillis() + it * 1000L)
                }
                reply(out, ver, dst, src, sport, resp)
            } catch (_: Exception) { }
        }
    }

    private fun forward(dns: ByteArray): ByteArray {
        val u = upstream
        if (!u.startsWith("https://")) return udp(u, dns)
        val plainHost = URL(u).host                      // 1.1.1.1 / 8.8.8.8 / 9.9.9.9 also answer plain DNS
        // Circuit breaker: after a DoH failure skip it for 60 s so queries don't each wait 4 s.
        if (fallback && System.currentTimeMillis() < dohDownUntil) return udp(plainHost, dns)
        return try {
            doh(u, dns)
        } catch (e: Exception) {
            if (!fallback) throw e
            dohDownUntil = System.currentTimeMillis() + 60_000
            udp(plainHost, dns)
        }
    }

    private fun udp(host: String, dns: ByteArray): ByteArray =
        DatagramSocket().use { s ->
            protect(s)                                   // bypass the VPN -> no loop
            s.soTimeout = 4000
            s.send(DatagramPacket(dns, dns.size, InetAddress.getByName(host), 53))
            val rb = ByteArray(4096)
            val rp = DatagramPacket(rb, rb.size)
            s.receive(rp)
            rb.copyOf(rp.length)
        }

    // DNS-over-HTTPS (RFC 8484). The URL must contain an IP literal so no DNS lookup is needed
    // (that lookup would come straight back into this VPN). Only the DNS /32 is routed into the
    // tunnel, so the HTTPS connection itself leaves over the normal network.
    private fun doh(url: String, dns: ByteArray): ByteArray {
        val c = URL(url).openConnection() as HttpsURLConnection
        try {
            c.requestMethod = "POST"; c.doOutput = true
            c.connectTimeout = 4000; c.readTimeout = 4000
            c.setRequestProperty("Content-Type", "application/dns-message")
            c.setRequestProperty("Accept", "application/dns-message")
            c.outputStream.use { it.write(dns) }
            if (c.responseCode != 200) throw IOException("DoH HTTP ${c.responseCode}")
            return c.inputStream.use { it.readBytes() }
        } finally { c.disconnect() }
    }

    /** Seconds to cache a response (clamped 30..600), or null if it must not be cached. */
    private fun ttlOf(r: ByteArray): Int? {
        if (r.size < 12) return null
        val rcode = r[3].toInt() and 0xF
        if ((r[2].toInt() and 0x02) != 0 || (rcode != 0 && rcode != 3)) return null   // truncated / error
        val qd = u16(r, 4); val an = u16(r, 6)
        var i = 12
        for (k in 0 until qd) { i = skipName(r, i) + 4; if (i > r.size) return null }
        if (an == 0) return 30
        var min = Long.MAX_VALUE
        for (k in 0 until an) {
            i = skipName(r, i)
            if (i + 10 > r.size) return null
            val ttl = (u16(r, i + 4).toLong() shl 16) or u16(r, i + 6).toLong()
            min = minOf(min, ttl)
            i += 10 + u16(r, i + 8)
        }
        return min.coerceIn(30L, 600L).toInt()
    }

    private fun skipName(d: ByteArray, start: Int): Int {
        var i = start
        while (i < d.size) {
            val len = d[i].toInt() and 0xFF
            if (len == 0) return i + 1
            if (len and 0xC0 == 0xC0) return i + 2
            i += 1 + len
        }
        return d.size
    }

    private fun parseQuestion(d: ByteArray): Triple<String, Int, Int>? {
        if (d.size < 17) return null
        var i = 12
        val sb = StringBuilder()
        while (i < d.size) {
            val len = d[i].toInt() and 0xFF
            if (len == 0) { i++; break }
            if (len and 0xC0 != 0 || i + 1 + len > d.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(d, i + 1, len, Charsets.ISO_8859_1))
            i += 1 + len
        }
        if (i + 4 > d.size) return null
        return Triple(sb.toString(), i + 4, u16(d, i))
    }

    private fun blockedAnswer(q: ByteArray, qEnd: Int, qType: Int): ByteArray {
        val rdata = when (qType) { 1 -> ByteArray(4); 28 -> ByteArray(16); else -> null }
        val r = ByteArrayOutputStream()
        r.write(q, 0, 2)
        r.write(0x81); r.write(0x80)
        r.write(0); r.write(1)
        r.write(0); r.write(if (rdata != null) 1 else 0)
        r.write(0); r.write(0); r.write(0); r.write(0)
        r.write(q, 12, qEnd - 12)
        if (rdata != null) {
            r.write(0xC0); r.write(0x0C)
            r.write(0); r.write(qType)
            r.write(0); r.write(1)
            r.write(0); r.write(0); r.write(0); r.write(60)
            r.write(0); r.write(rdata.size)
            r.write(rdata)
        }
        return r.toByteArray()
    }

    @Synchronized
    private fun reply(out: FileOutputStream, ver: Int, src: ByteArray, dst: ByteArray, dport: Int, dns: ByteArray) {
        val ul = 8 + dns.size
        if (ver == 4) {
            val total = 20 + ul
            val b = ByteArray(total)
            b[0] = 0x45; b[2] = (total shr 8).toByte(); b[3] = total.toByte()
            b[6] = 0x40; b[8] = 64; b[9] = 17
            System.arraycopy(src, 0, b, 12, 4); System.arraycopy(dst, 0, b, 16, 4)
            var sum = 0
            for (i in 0 until 20 step 2) sum += u16(b, i)
            val ck = fold(sum)
            b[10] = (ck shr 8).toByte(); b[11] = ck.toByte()
            b[21] = 53
            b[22] = (dport shr 8).toByte(); b[23] = dport.toByte()
            b[24] = (ul shr 8).toByte(); b[25] = ul.toByte()
            System.arraycopy(dns, 0, b, 28, dns.size)
            out.write(b)
        } else {
            val b = ByteArray(40 + ul)
            b[0] = 0x60; b[4] = (ul shr 8).toByte(); b[5] = ul.toByte(); b[6] = 17; b[7] = 64
            System.arraycopy(src, 0, b, 8, 16); System.arraycopy(dst, 0, b, 24, 16)
            b[41] = 53
            b[42] = (dport shr 8).toByte(); b[43] = dport.toByte()
            b[44] = (ul shr 8).toByte(); b[45] = ul.toByte()
            System.arraycopy(dns, 0, b, 48, dns.size)
            var sum = 0
            for (i in 8 until 40 step 2) sum += u16(b, i)
            sum += ul + 17
            var i = 40
            while (i < b.size) { sum += if (i + 1 < b.size) u16(b, i) else (b[i].toInt() and 0xFF) shl 8; i += 2 }
            var ck = fold(sum); if (ck == 0) ck = 0xFFFF
            b[46] = (ck shr 8).toByte(); b[47] = ck.toByte()
            out.write(b)
        }
    }

    private fun fold(s: Int): Int { var x = s; while (x shr 16 != 0) x = (x and 0xFFFF) + (x shr 16); return x.inv() and 0xFFFF }
    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
}
