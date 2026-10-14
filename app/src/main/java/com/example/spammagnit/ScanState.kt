package com.example.spammagnit

enum class Stage { IDLE, COLLECTING, SORTING, SCANNING, DONE, ERROR, STOPPED }

data class ScanState(
    val stage: Stage = Stage.IDLE,

    // ---------- Stage 1: collection ----------
    val collectTotal: Int = 0,
    val collectDone: Int = 0,
    val collectCurrentIp: String? = null,
    val collectedDomains: Int = 0,

    // ---------- Stage 1.5: sorting and filtering ----------
    val sortTotal: Int = 0,
    val sortDone: Int = 0,

    // ---------- Stage 2: scanning ----------
    val scanTotal: Int = 0,
    val scanDone: Int = 0,
    val okHttps: Int = 0,
    val okHttp: Int = 0,
    val failed: Int = 0,

    val recent: List<CheckResult> = emptyList(),
    val startedAt: Long = 0L,
    val error: String? = null,
) {
    val collectProgress: Float
        get() = if (collectTotal == 0) 0f else collectDone.toFloat() / collectTotal

    val sortProgress: Float
        get() = if (sortTotal == 0) 0f else sortDone.toFloat() / sortTotal

    val scanProgress: Float
        get() = if (scanTotal == 0) 0f else scanDone.toFloat() / scanTotal
}