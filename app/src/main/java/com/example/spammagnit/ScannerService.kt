package com.example.spammagnit

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File

class ScannerService : Service() {

    companion object {
        const val CHANNEL_ID = "scanner_channel"
        const val NOTIF_ID = 1
        const val ACTION_STOP = "com.example.spammagnit.STOP"

        // Renew the WakeLock every 10 minutes instead of using a 1-hour timeout.
        private const val WAKELOCK_RENEW_MS = 10 * 60 * 1000L

        private val _stateFlow = MutableStateFlow(ScanState())

        /** Public read-only access to the scanner state. */
        val stateFlow: StateFlow<ScanState> = _stateFlow.asStateFlow()

        @Volatile
        var isRunning: Boolean = false
            private set
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var scanJob: Job? = null
    private var notifyJob: Job? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopScan()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                if (!isRunning) startScan()
            }
        }
        return START_NOT_STICKY
    }

    private fun startScan() {
        isRunning = true

        // Always start from scratch — explicit reset instead of a partial copy.
        _stateFlow.value = ScanState(
            stage = Stage.COLLECTING,
            collectTotal = Targets.IPS.size,
            startedAt = System.currentTimeMillis(),
        )

        startForeground(NOTIF_ID, buildNotification(_stateFlow.value))

        acquireWakeLock()

        scanJob = scope.launch {
            try {
                val scanner = Scanner(
                    thcCacheDir = File(applicationContext.cacheDir, "thc").apply { mkdirs() },
                    state = _stateFlow,
                )
                scanner.run()
            } catch (e: CancellationException) {
                // Cancelled by the user (Stop button) — not an error.
                // stopScan() has already set STOPPED and preserved progress.
                throw e
            } catch (e: Exception) {
                // Don't overwrite STOPPED if the user has already stopped.
                if (isRunning) {
                    _stateFlow.value = _stateFlow.value.copy(
                        stage = Stage.ERROR,
                        error = e.message ?: "unknown error",
                    )
                }
            } finally {
                isRunning = false
                // Do not touch stage here:
                //   DONE    — set by Scanner.run();
                //   STOPPED — set by stopScan();
                //   ERROR   — set by the catch block above.
                updateNotification(_stateFlow.value)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }

        notifyJob = scope.launch {
            var lastRenew = System.currentTimeMillis()
            while (isRunning) {
                delay(1000)
                updateNotification(_stateFlow.value)

                // Keep the WakeLock alive while the job is running.
                val now = System.currentTimeMillis()
                if (now - lastRenew >= WAKELOCK_RENEW_MS) {
                    renewWakeLock()
                    lastRenew = now
                }
            }
        }
    }

    private fun stopScan() {
        isRunning = false

        // Set STOPPED first — progress is preserved as-is.
        _stateFlow.value = _stateFlow.value.copy(stage = Stage.STOPPED)

        releaseResources()
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    /**
     * Releases resources without changing the stage.
     * Used both on user stop and in onDestroy.
     */
    private fun releaseResources() {
        scanJob?.cancel()
        notifyJob?.cancel()
        scanJob = null
        notifyJob = null

        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    override fun onDestroy() {
        // Do NOT call stopScan() here — it would overwrite DONE/ERROR with STOPPED.
        releaseResources()
        scope.cancel()
        super.onDestroy()
    }

    // ---------- WakeLock ----------

    private fun acquireWakeLock() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "scanner:lock").apply {
            setReferenceCounted(false)
            // No timeout — renewed manually in notifyJob.
            acquire()
        }
    }

    private fun renewWakeLock() {
        val wl = wakeLock ?: return
        if (!wl.isHeld) {
            wl.acquire()
        }
    }

    // ---------- Notifications ----------

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                CHANNEL_ID,
                "Scanner",
                NotificationManager.IMPORTANCE_LOW,
            )
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(ch)
        }
    }

    private fun buildNotification(s: ScanState): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, ScannerService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val text = when (s.stage) {
            Stage.COLLECTING ->
                "Сбор: ${s.collectDone}/${s.collectTotal} IP (${s.collectedDomains} доменов)"
            Stage.SORTING ->
                "Сортировка и фильтр…"
            Stage.SCANNING ->
                "Скан: ${s.scanDone}/${s.scanTotal}  OK: ${s.okHttps + s.okHttp}  FAIL: ${s.failed}"
            Stage.DONE ->
                "Готово. OK: ${s.okHttps + s.okHttp}, FAIL: ${s.failed}"
            Stage.ERROR ->
                "Ошибка: ${s.error}"
            Stage.STOPPED ->
                "Остановлено. OK: ${s.okHttps + s.okHttp}, FAIL: ${s.failed}"
            else ->
                "Ожидание"
        }

        val (done, total) = when (s.stage) {
            Stage.SCANNING -> s.scanDone to s.scanTotal
            Stage.COLLECTING -> s.collectDone to s.collectTotal
            Stage.SORTING -> s.sortDone to s.sortTotal
            else -> 0 to 0
        }

        val ongoing = s.stage == Stage.COLLECTING ||
                s.stage == Stage.SORTING ||
                s.stage == Stage.SCANNING

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Scanner")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(ongoing)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(0, "Стоп", stopIntent)

        if (total > 0) {
            builder.setProgress(total, done, false)
        } else {
            // Reset the progress bar when total == 0.
            builder.setProgress(0, 0, false)
        }

        return builder.build()
    }

    private fun updateNotification(s: ScanState) {
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
            .notify(NOTIF_ID, buildNotification(s))
    }
}