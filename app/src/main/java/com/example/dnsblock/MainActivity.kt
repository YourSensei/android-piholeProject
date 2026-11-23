package com.example.dnsblock

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.View
import android.widget.*
import java.text.DateFormat
import java.util.Date
import kotlin.concurrent.thread

class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var toggle: Button
    private lateinit var adapter: ArrayAdapter<String>
    private var shown: List<QueryLog.Entry> = emptyList()
    private var lastVersion = -1
    private val ui = Handler(Looper.getMainLooper())
    private val tick = object : Runnable { override fun run() { refresh(); ui.postDelayed(this, 1000) } }
    private val sp by lazy { getSharedPreferences("cfg", MODE_PRIVATE) }

    private val presets = listOf(
        "Cloudflare (DoH, encrypted)" to "https://1.1.1.1/dns-query",
        "Google (DoH, encrypted)" to "https://8.8.8.8/dns-query",
        "Quad9 (DoH, encrypted)" to "https://9.9.9.9/dns-query",
        "Cloudflare (plain)" to "1.1.1.1",
        "Custom / my Pi-hole" to ""
    )

    private fun valid(v: String): Boolean {
        val ip = "(\\d{1,3}\\.){3}\\d{1,3}"
        return if (v.startsWith("https://")) Regex("^https://$ip(:\\d+)?/\\S*$").matches(v)
        else Regex("^$ip$").matches(v) || (v.contains(':') && Regex("^[0-9a-fA-F:]+$").matches(v))
    }

    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 2)
        Blocklist.load(this)
        if (sp.getBoolean("autoupdate", true)) Updater.schedule(this)

        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 16) }
        status = TextView(this).apply { textSize = 16f }
        toggle = Button(this).apply { setOnClickListener { onToggle() } }
        val upd = Button(this).apply {
            text = "Update blocklist"
            setOnClickListener {
                text = "Downloading..."
                thread {
                    val ok = Blocklist.update(applicationContext)
                    Notifier.updateResult(applicationContext, ok)
                    ui.post { text = if (ok) "Updated: ${Blocklist.size} domains" else "Update failed" }
                }
            }
        }
        val btns = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        btns.addView(toggle, LinearLayout.LayoutParams(0, -2, 1f)); btns.addView(upd, LinearLayout.LayoutParams(0, -2, 1f))

        val up = EditText(this).apply {
            hint = "https://IP/dns-query  or  plain IP"
            setText(sp.getString("upstream", presets[0].second))
            inputType = InputType.TYPE_CLASS_TEXT
        }
        val sel = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, presets.map { it.first })
            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                var first = true
                override fun onItemSelected(p: AdapterView<*>?, v: View?, pos: Int, id: Long) {
                    if (first) { first = false; return }
                    val u = presets[pos].second
                    if (u.isNotEmpty()) up.setText(u) else up.setText("")
                }
                override fun onNothingSelected(p: AdapterView<*>?) {}
            }
        }
        val save = Button(this).apply {
            text = "Save"
            setOnClickListener {
                val v = up.text.toString().trim()
                if (valid(v)) {
                    sp.edit().putString("upstream", v).apply(); DnsVpnService.upstream = v
                    Toast.makeText(context, "Upstream: $v", Toast.LENGTH_SHORT).show()
                } else Toast.makeText(context, "Use an IP address or https://<IP>/dns-query", Toast.LENGTH_LONG).show()
            }
        }
        val upRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        upRow.addView(up, LinearLayout.LayoutParams(0, -2, 1f)); upRow.addView(save)

        val boot = CheckBox(this).apply {
            text = "Start on boot"
            isChecked = sp.getBoolean("boot", false)
            setOnCheckedChangeListener { _, c -> sp.edit().putBoolean("boot", c).apply() }
        }
        val auto = CheckBox(this).apply {
            text = "Update blocklist weekly (Wi-Fi)"
            isChecked = sp.getBoolean("autoupdate", true)
            setOnCheckedChangeListener { _, c ->
                sp.edit().putBoolean("autoupdate", c).apply()
                if (c) Updater.schedule(context) else Updater.cancel(context)
            }
        }
        val fb = CheckBox(this).apply {
            text = "If DoH fails, fall back to plain DNS (less private)"
            isChecked = sp.getBoolean("fallback", false)
            setOnCheckedChangeListener { _, c -> sp.edit().putBoolean("fallback", c).apply(); DnsVpnService.fallback = c }
        }
        val hint = TextView(this).apply { text = "Query log - tap a domain to block/allow it"; setPadding(0, 16, 0, 8) }

        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, ArrayList<String>())
        val list = ListView(this).apply {
            this.adapter = this@MainActivity.adapter
            setOnItemClickListener { _, _, pos, _ ->
                val e = shown.getOrNull(pos) ?: return@setOnItemClickListener
                val nowBlocked = Blocklist.isBlocked(e.name)
                Blocklist.setRule(context, e.name, !nowBlocked)
                Toast.makeText(context, (if (nowBlocked) "Allowed: " else "Blocked: ") + e.name, Toast.LENGTH_SHORT).show()
            }
        }
        col.addView(status); col.addView(btns); col.addView(sel); col.addView(upRow)
        col.addView(boot); col.addView(auto); col.addView(fb); col.addView(hint)
        col.addView(list, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(col)
    }

    override fun onResume() { super.onResume(); ui.post(tick) }
    override fun onPause() { super.onPause(); ui.removeCallbacks(tick) }

    private fun refresh() {
        val on = DnsVpnService.running
        toggle.text = if (on) "Stop" else "Start"
        val t = Blocklist.lastUpdated(this)
        val upd = if (t == 0L) "built-in list" else DateFormat.getDateInstance().format(Date(t))
        status.text = (if (on) "Active  -  blocked ${DnsVpnService.blocked.get()} / allowed ${DnsVpnService.allowed.get()} (cache hits ${DnsVpnService.cacheHits.get()})" else "Off") +
            "\nList: ${Blocklist.size} domains, $upd"
        val v = QueryLog.version.get()
        if (v != lastVersion) {
            lastVersion = v
            shown = QueryLog.snapshot()
            adapter.clear()
            adapter.addAll(shown.map { (if (it.blocked) "\u2717  " else "\u2713  ") + it.name })
        }
    }

    private fun onToggle() {
        if (DnsVpnService.running) {
            startService(Intent(this, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
        } else {
            val i = VpnService.prepare(this)
            if (i != null) startActivityForResult(i, 1) else startVpn()
        }
    }

    override fun onActivityResult(req: Int, res: Int, d: Intent?) { if (req == 1 && res == RESULT_OK) startVpn() }
    private fun startVpn() {
        val s = Intent(this, DnsVpnService::class.java)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(s) else startService(s)
    }
}
