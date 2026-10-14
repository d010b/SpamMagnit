package com.example.spammagnit

enum class Status { OK_HTTPS, OK_HTTP, FAIL }

data class CheckResult(
    val domain: String,
    val ip: String,
    val status: Status,
    val httpCode: Int?,
    val bodySize: Long,
    val elapsedMs: Long,
    val error: String? = null,
)