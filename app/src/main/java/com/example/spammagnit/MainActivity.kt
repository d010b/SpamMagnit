package com.example.spammagnit

import android.Manifest
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private val notifPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            MaterialTheme {
                ScannerScreen()
            }
        }
    }
}

@Composable
fun ScannerScreen() {
    val state by ScannerService.stateFlow.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    val isRunning = state.stage == Stage.COLLECTING ||
            state.stage == Stage.SORTING ||
            state.stage == Stage.SCANNING

    var elapsed by remember { mutableStateOf(0L) }

    // ---------- Индикация Wi-Fi ----------
    var wifiOn by remember { mutableStateOf(isWifiEnabled(ctx)) }

    DisposableEffect(Unit) {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                wifiOn = isWifiEnabled(ctx)
            }

            override fun onLost(network: Network) {
                wifiOn = isWifiEnabled(ctx)
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities,
            ) {
                wifiOn = isWifiEnabled(ctx)
            }
        }

        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .build()

        runCatching { cm.registerNetworkCallback(request, callback) }

        // Fallback: раз в 2 секунды перепроверяем состояние модуля Wi-Fi.
        val job = scope.launch {
            while (isActive) {
                delay(2000)
                wifiOn = isWifiEnabled(ctx)
            }
        }

        onDispose {
            runCatching { cm.unregisterNetworkCallback(callback) }
            job.cancel()
        }
    }

    // ---------- Таймер ----------
    LaunchedEffect(state.stage, state.startedAt) {
        if (isRunning) {
            while (isActive && isRunning) {
                elapsed = System.currentTimeMillis() - state.startedAt
                delay(500)
            }
            elapsed = System.currentTimeMillis() - state.startedAt
        } else {
            if (state.startedAt > 0L &&
                (state.stage == Stage.DONE || state.stage == Stage.STOPPED)
            ) {
                elapsed = System.currentTimeMillis() - state.startedAt
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("SpamMagnit-process", fontSize = 24.sp)
        Text("IP в списке: ${Targets.IPS.size}", fontSize = 14.sp)

        // ---------- Предупреждение о включённом Wi-Fi ----------
        if (wifiOn) {
            Text(
                text = " Выключите WIFI, иначе дальнейшая работа бессмысленна.",
                color = Color(0xFFC62828),
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
            )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    val intent = Intent(ctx, ScannerService::class.java)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        ctx.startForegroundService(intent)
                    } else {
                        ctx.startService(intent)
                    }
                },
                enabled = !isRunning,
            ) {
                Text("Старт")
            }

            OutlinedButton(
                onClick = {
                    val intent = Intent(ctx, ScannerService::class.java)
                        .setAction(ScannerService.ACTION_STOP)
                    ctx.startService(intent)
                },
                enabled = isRunning,
            ) {
                Text("Стоп")
            }
        }

        // ---------- Этап 1: сбор ----------
        if (state.stage == Stage.COLLECTING ||
            state.stage == Stage.SORTING ||
            state.stage == Stage.SCANNING ||
            state.stage == Stage.DONE ||
            state.stage == Stage.STOPPED
        ) {
            val current = state.collectCurrentIp?.let { "  → $it" } ?: ""
            Text(
                "Этап 1: ${state.collectDone}/${state.collectTotal} IP " +
                        "(${state.collectedDomains} доменов)$current",
                fontSize = 13.sp,
            )
            LinearProgressIndicator(
                progress = { state.collectProgress },
                modifier = Modifier.fillMaxWidth(),
            )
        }

        // ---------- Этап 1.5: сортировка ----------
        if (state.stage == Stage.SORTING) {
            Text("Сортировка и фильтр…", fontSize = 13.sp)
            LinearProgressIndicator(
                progress = { state.sortProgress },
                modifier = Modifier.fillMaxWidth(),
            )
        }

        // ---------- Этап 2: скан ----------
        if (state.stage == Stage.SCANNING ||
            state.stage == Stage.DONE ||
            state.stage == Stage.STOPPED
        ) {
            Text(
                "Этап 2: ${state.scanDone}/${state.scanTotal}",
                fontSize = 13.sp,
            )
            LinearProgressIndicator(
                progress = { state.scanProgress },
                modifier = Modifier.fillMaxWidth(),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "OK HTTPS: ${state.okHttps}",
                    color = Color(0xFF2E7D32),
                    fontSize = 13.sp,
                )
                Text(
                    "OK HTTP: ${state.okHttp}",
                    color = Color(0xFFF9A825),
                    fontSize = 13.sp,
                )
                Text(
                    "FAIL: ${state.failed}",
                    color = Color(0xFFC62828),
                    fontSize = 13.sp,
                )
            }
            Text("Прошло: ${elapsed / 1000} сек", fontSize = 12.sp)
        }

        // ---------- Статус ----------
        when (state.stage) {
            Stage.DONE -> {
                Text(
                    "Завершено. OK: ${state.okHttps + state.okHttp}, FAIL: ${state.failed}",
                    color = Color(0xFF2E7D32),
                    fontSize = 13.sp,
                )
            }
            Stage.STOPPED -> {
                Text(
                    "Остановлено вручную. OK: ${state.okHttps + state.okHttp}, FAIL: ${state.failed}",
                    color = Color(0xFF757575),
                    fontSize = 13.sp,
                )
            }
            Stage.ERROR -> {
                Text(
                    "Ошибка: ${state.error}",
                    color = Color(0xFFC62828),
                    fontSize = 13.sp,
                )
            }
            else -> { /* ничего */ }
        }

        HorizontalDivider()

        // ---------- Лог ----------
        Text("Лог:", fontSize = 13.sp)
        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
        ) {
            items(state.recent) { r ->
                val (color, label) = when (r.status) {
                    Status.OK_HTTPS -> Color(0xFF2E7D32) to "HTTPS ${r.httpCode}"
                    Status.OK_HTTP -> Color(0xFFF9A825) to "HTTP ${r.httpCode}"
                    Status.FAIL -> Color(0xFFC62828) to "FAIL"
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 2.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        r.domain,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        modifier = Modifier.weight(1f),
                    )
                    Text(label, color = color, fontSize = 12.sp)
                    Text("${r.elapsedMs}ms", fontSize = 11.sp)
                }
            }
        }
    }
}

/**
 * Проверяет, включён ли модуль Wi-Fi.
 *
 * Использует deprecated `WifiManager.isWifiEnabled`, но это
 * единственный способ узнать состояние МОДУЛЯ (а не подключения
 * к конкретной сети). Требует ACCESS_WIFI_STATE.
 */
private fun isWifiEnabled(ctx: Context): Boolean {
    val wm = ctx.applicationContext
        .getSystemService(Context.WIFI_SERVICE) as WifiManager
    @Suppress("DEPRECATION")
    return wm.isWifiEnabled
}