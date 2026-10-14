package com.example.spammagnit

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File

@Serializable
data class ThcRequest(
    @SerialName("ip_address") val ipAddress: String,
    val limit: Int,
    @SerialName("page_state") val pageState: String? = null,
)

@Serializable
data class ThcResponse(
    val comment: String = "",
    @SerialName("processed_ip_address") val processedIp: String = "",
    @SerialName("matching_records") val matchingRecords: Int = 0,
    val domains: List<ThcDomain> = emptyList(),
    @SerialName("next_page_state") val nextPageState: String? = null,
)

@Serializable
data class ThcDomain(
    @SerialName("apex_domain") val apexDomain: String = "",
    val domain: String = "",
)

class ThcRdnsClient(
    private val client: OkHttpClient,
    private val cacheDir: File,
) {
    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

    // Burst: 240 requests without pauses, then 0.5 req/sec.
    private val rateLimitMutex = Mutex()
    private var burstLeft = 240
    private var burstResetAt = System.currentTimeMillis() + 60_000L
    private val inBurstDelayMs = 20L
    private val outOfBurstDelayMs = 2_000L

    // JSON pagination (slow path, fallback).
    private val pageLimit = 100
    private val maxPages = 1000
    private val maxRetries429 = 2
    private val retryDelay429Ms = 3_000L

    // CSV (fast path) — rdns only.
    private val csvBaseUrl = "https://ip.thc.org/api/v1/download"
    private val csvLimit = 50_000

    /**
     * Collects domains for a single IP.
     *
     * Strategy:
     *  - maxDomains > 100 → CSV (1 request, up to 50,000 records).
     *  - maxDomains ≤ 100 → JSON (1 request).
     *  - CSV failed → JSON pagination as fallback.
     */
    suspend fun collectAll(
        ip: String,
        maxDomains: Int,
        onProgress: (Int) -> Unit = {},
    ): List<String> = withContext(Dispatchers.IO) {
        // readCache trims lines and caps the result by maxDomains.
        readCache(ip, maxDomains)?.let {
            onProgress(it.size)
            return@withContext it
        }

        // ---------- Fast path: CSV ----------
        if (maxDomains > pageLimit) {
            val csvResult = fetchCsv(ip, maxDomains)
            if (csvResult.isNotEmpty()) {
                writeCache(ip, csvResult)
                onProgress(csvResult.size)
                return@withContext csvResult
            }
            // CSV failed — fall through to JSON pagination.
        }

        // ---------- Slow path: JSON + pagination ----------
        val all = LinkedHashSet<String>()
        var pageState: String? = null
        var page = 0
        var retriesOnCurrentPage = 0

        while (page < maxPages) {
            if (all.size >= maxDomains) break

            rateLimit()

            val bodyStr = json.encodeToString(
                ThcRequest.serializer(),
                ThcRequest(ipAddress = ip, limit = pageLimit, pageState = pageState),
            )
            val req = Request.Builder()
                .url("https://ip.thc.org/api/v1/lookup")
                .post(bodyStr.toRequestBody(jsonMedia))
                .header("User-Agent", "scanner-android/1.0")
                .build()

            var retryThisPage = false

            val parsed: ThcResponse? = try {
                client.newCall(req).execute().use { resp ->
                    when {
                        resp.code == 429 -> {
                            retriesOnCurrentPage++
                            if (retriesOnCurrentPage >= maxRetries429) null
                            else { retryThisPage = true; null }
                        }
                        !resp.isSuccessful -> null
                        else -> {
                            val text = resp.body?.string()
                            if (text.isNullOrEmpty()) null
                            else runCatching {
                                json.decodeFromString(ThcResponse.serializer(), text)
                            }.getOrNull()
                        }
                    }
                }
            } catch (e: Exception) { null }

            if (retryThisPage) {
                delay(retryDelay429Ms)
                continue
            }
            if (parsed == null) break

            retriesOnCurrentPage = 0

            parsed.domains.forEach { d ->
                val name = d.domain.trim().lowercase()
                if (name.isNotEmpty() &&
                    name.contains(".") &&
                    !name.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$"))
                ) {
                    all += name
                }
            }
            page++
            onProgress(all.size)

            if (all.size >= maxDomains) break

            pageState = parsed.nextPageState
            if (pageState.isNullOrBlank()) break
            if (parsed.matchingRecords > 0 && all.size >= parsed.matchingRecords) break
        }

        val result = all.toList().take(maxDomains)
        writeCache(ip, result)
        onProgress(result.size)
        result
    }

    /**
     * CSV endpoint: up to 50,000 records in a single request, no pagination.
     *
     * Response format (positional, header hidden via hide_header=true):
     *   apex_domain,domain,tld,country,city,asn,organization,ip_address
     *
     * IMPORTANT: organization may contain a comma ("REG.RU, Ltd"),
     * so split(',') would produce extra columns. We only parse:
     *   - domain (between the 1st and 2nd commas)
     *   - ip_address (after the last comma)
     */
    private fun fetchCsv(ip: String, maxDomains: Int): List<String> {
        val limit = minOf(maxDomains, csvLimit)
        val url = "$csvBaseUrl" +
                "?ip_address=$ip" +
                "&limit=$limit" +
                "&hide_header=true"

        val req = Request.Builder()
            .url(url)
            .header("Accept", "text/csv")
            .header("User-Agent", "scanner-android/1.0")
            .build()

        return try {
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return emptyList()
                val body = resp.body?.string() ?: return emptyList()

                // The CSV endpoint may return a JSON error despite
                // Accept: text/csv. Check for that.
                if (body.trimStart().startsWith("{")) return emptyList()

                val out = LinkedHashSet<String>()

                lineLoop@ for (raw in body.lineSequence()) {
                    val line = raw.trim()
                    if (line.isEmpty()) continue@lineLoop

                    // 1st comma — end of apex_domain.
                    val firstComma = line.indexOf(',')
                    if (firstComma < 0) continue@lineLoop

                    // 2nd comma — end of domain.
                    val secondComma = line.indexOf(',', firstComma + 1)
                    if (secondComma < 0) continue@lineLoop
                    val domain = line.substring(firstComma + 1, secondComma)
                        .trim()
                        .lowercase()

                    // Last comma — start of ip_address.
                    val lastComma = line.lastIndexOf(',')
                    if (lastComma <= secondComma) continue@lineLoop
                    val ipCol = line.substring(lastComma + 1).trim()

                    // Sanity: ip_address must match the requested one.
                    if (ipCol != ip) continue@lineLoop

                    if (domain.isEmpty() ||
                        !domain.contains(".") ||
                        domain.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$"))
                    ) continue@lineLoop

                    out += domain
                    if (out.size >= maxDomains) break@lineLoop
                }

                out.toList()
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    private suspend fun rateLimit() {
        rateLimitMutex.withLock {
            val now = System.currentTimeMillis()
            if (now > burstResetAt) {
                burstLeft = 240
                burstResetAt = now + 60_000L
            }
            if (burstLeft > 0) {
                burstLeft--
                delay(inBurstDelayMs)
            } else {
                delay(outOfBurstDelayMs)
            }
        }
    }

    // ---------- Cache ----------

    private fun cacheFile(ip: String) = File(cacheDir, "thc_$ip.json")

    /**
     * Trims lines, drops empties, and caps the result by maxDomains.
     */
    private fun readCache(ip: String, maxDomains: Int): List<String>? {
        val f = cacheFile(ip)
        if (!f.exists()) return null
        if (System.currentTimeMillis() - f.lastModified() > 24 * 3600_000L) return null
        return runCatching {
            f.readLines()
                .asSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .take(maxDomains)
                .toList()
        }.getOrNull()
    }

    private fun writeCache(ip: String, domains: List<String>) {
        runCatching {
            cacheDir.mkdirs()
            cacheFile(ip).writeText(domains.joinToString("\n"))
        }
    }
}