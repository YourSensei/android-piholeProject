package com.example.dnsblock

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, i: Intent) {
        if (i.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!ctx.getSharedPreferences("cfg", Context.MODE_PRIVATE).getBoolean("boot", false)) return
        if (VpnService.prepare(ctx) != null) return   // permission not granted yet
        val s = Intent(ctx, DnsVpnService::class.java)
        if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(s) else ctx.startService(s)
    }
}
