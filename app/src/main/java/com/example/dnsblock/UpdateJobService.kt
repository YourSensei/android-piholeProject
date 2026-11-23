package com.example.dnsblock

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context

class UpdateJobService : JobService() {
    override fun onStartJob(p: JobParameters): Boolean {
        Thread {
            val ok = Blocklist.update(applicationContext)
            Notifier.updateResult(applicationContext, ok)
            jobFinished(p, !ok)          // retry later if the download failed
        }.start()
        return true
    }
    override fun onStopJob(p: JobParameters) = true
}

object Updater {
    private const val ID = 42
    fun schedule(ctx: Context) {
        val js = ctx.getSystemService(JobScheduler::class.java)
        if (js.getPendingJob(ID) != null) return
        js.schedule(
            JobInfo.Builder(ID, ComponentName(ctx, UpdateJobService::class.java))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)   // Wi-Fi only
                .setPeriodic(7L * 24 * 3600 * 1000)
                .setPersisted(true)
                .build()
        )
    }
    fun cancel(ctx: Context) { ctx.getSystemService(JobScheduler::class.java).cancel(ID) }
}

object Notifier {
    fun updateResult(ctx: Context, ok: Boolean) {
        try {
            val nm = ctx.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel("upd", "Blocklist updates", NotificationManager.IMPORTANCE_LOW))
            val text = if (ok) "Blocklist updated: ${Blocklist.size} domains" else "Blocklist update failed - will retry"
            val n = Notification.Builder(ctx, "upd")
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("DNS Blocker")
                .setContentText(text)
                .setAutoCancel(true).build()
            nm.notify(2, n)
        } catch (_: Exception) { }   // notification permission denied -> silently skip
    }
}
