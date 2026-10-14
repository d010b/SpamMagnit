package com.example.spammagnit

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import okhttp3.OkHttpClient
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

class Scanner(
    private val thcCacheDir: File,
    private val state: MutableStateFlow<ScanState>,
) {
    companion object {
        // Hard limit of domains collected per single IP.
        const val MAX_DOMAINS_PER_IP = 21_000

        // How many IPs to collect concurrently.
        const val CONCURRENT_IPS = 2

        // How many scan checks to run in parallel.
        private const val CONCURRENT_SCANS = 12

        // No more than 2 domains per single apex.
        private const val MAX_PER_APEX = 2

        // Two-level public suffixes.
        private val TWO_LEVEL_TLDS = setOf(
            "co.uk", "org.uk", "ac.uk", "gov.uk",
            "com.ru", "net.ru", "org.ru", "msk.ru", "spb.ru",
            "com.au", "net.au", "org.au",
            "com.br", "com.cn", "com.tr", "com.ua", "com.pl",
            "co.jp", "co.kr", "co.in", "co.nz", "co.za",
            "com.mx", "com.ar", "com.sg", "com.hk", "com.tw",
        )

        // Russian TLDs: only domains in these zones are kept.
        private val RU_TLDS = setOf(
            "ru", "su",
            "рф", "xn--p1ai",
            "рус", "xn--p1acf",
        )
    }

    private val thcClient = ThcRdnsClient(
        client = OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .callTimeout(15, TimeUnit.SECONDS)
            .build(),
        cacheDir = thcCacheDir,
    )

    suspend fun run() {
        // ---------- Always start from scratch ----------
        state.update {
            it.copy(
                stage = Stage.COLLECTING,
                collectTotal = Targets.IPS.size,
                collectDone = 0,
                collectCurrentIp = null,
                collectedDomains = 0,
                sortTotal = 0,
                sortDone = 0,
                scanTotal = 0,
                scanDone = 0,
                okHttps = 0,
                okHttp = 0,
                failed = 0,
                recent = emptyList(),
                startedAt = System.currentTimeMillis(),
                error = null,
            )
        }

        // ============================================================
        // STAGE 1: collect domains
        // ============================================================
        val ipToDomains = ConcurrentHashMap<String, List<String>>()

        coroutineScope {
            Targets.IPS
                .chunked(CONCURRENT_IPS)
                .forEach { chunk ->
                    chunk.map { ip ->
                        async(Dispatchers.IO) {
                            currentCoroutineContext().ensureActive()

                            state.update { it.copy(collectCurrentIp = ip) }

                            val domains = thcClient.collectAll(
                                ip = ip,
                                maxDomains = MAX_DOMAINS_PER_IP,
                            ) { collectedSoFar ->
                                state.update { s ->
                                    val others = ipToDomains.values.sumOf { l -> l.size }
                                    s.copy(collectedDomains = others + collectedSoFar)
                                }
                            }

                            ipToDomains[ip] = domains

                            state.update { s ->
                                s.copy(
                                    collectDone = s.collectDone + 1,
                                    collectedDomains = ipToDomains.values.sumOf { l -> l.size },
                                )
                            }
                        }
                    }.awaitAll()
                }
        }

        // If the job was cancelled during collection, bail out without
        // touching the stage.
        currentCoroutineContext().ensureActive()

        // ============================================================
        // STAGE 1.5: sorting + filtering (with progress)
        // ============================================================
        val allRaw = ipToDomains.values.sumOf { it.size }
        state.update {
            it.copy(
                stage = Stage.SORTING,
                sortTotal = allRaw,
                sortDone = 0,
            )
        }

        val cleanedIpToDomains: Map<String, List<String>> = Targets.IPS.associateWith { ip ->
            val raw = ipToDomains[ip].orEmpty()
            normalizeDomains(raw) { step ->
                state.update { s -> s.copy(sortDone = s.sortDone + step) }
            }
        }

        // Safety net for the empty-input case: progress should already
        // be correct, but make sure sortDone == sortTotal at the end.
        state.update { s ->
            val remaining = (s.sortTotal - s.sortDone).coerceAtLeast(0)
            if (remaining > 0) s.copy(sortDone = s.sortTotal) else s
        }

        // Cancellation check before the scanning stage.
        currentCoroutineContext().ensureActive()

        val totalAfterFilter = cleanedIpToDomains.values.sumOf { it.size }
        state.update { it.copy(collectedDomains = totalAfterFilter) }

        // ============================================================
        // STAGE 2: scanning
        // ============================================================
        val pairs: List<Pair<String, String>> = Targets.IPS.flatMap { ip ->
            cleanedIpToDomains[ip].orEmpty().map { ip to it }
        }

        val fixedDns = FixedDns(
            pairs.associate { (ip, domain) -> domain to ip }
        )
        val checker = DomainChecker(fixedDns)

        state.update {
            it.copy(
                stage = Stage.SCANNING,
                scanTotal = pairs.size,
                scanDone = 0,
                okHttps = 0,
                okHttp = 0,
                failed = 0,
            )
        }

        val semaphore = Semaphore(CONCURRENT_SCANS)

        coroutineScope {
            pairs.map { (ip, domain) ->
                async(Dispatchers.IO) {
                    semaphore.withPermit {
                        // Don't start a new check if the coroutine is cancelled.
                        currentCoroutineContext().ensureActive()

                        val result = checker.check(domain, ip)

                        // StateFlow.update does not check for cancellation,
                        // so explicitly bail out if the job is no longer active.
                        if (!currentCoroutineContext().isActive) return@withPermit

                        state.update { s ->
                            s.copy(
                                scanDone = (s.scanDone + 1).coerceAtMost(s.scanTotal),
                                okHttps = s.okHttps + if (result.status == Status.OK_HTTPS) 1 else 0,
                                okHttp = s.okHttp + if (result.status == Status.OK_HTTP) 1 else 0,
                                failed = s.failed + if (result.status == Status.FAIL) 1 else 0,
                                recent = (listOf(result) + s.recent).take(20),
                            )
                        }
                    }
                }
            }.awaitAll()
        }

        // Don't overwrite STOPPED/ERROR with DONE if the job was cancelled.
        if (currentCoroutineContext().isActive) {
            state.update { it.copy(stage = Stage.DONE) }
        }
    }

    // ============================================================
    // Sorting and filtering (with progress)
    // ============================================================

    /**
     * Cleans, filters by RU zones, removes mail subdomains, sorts,
     * and keeps no more than MAX_PER_APEX domains per apex.
     *
     * Progress grows monotonically and sums up to input.size.
     * Budget split:
     *   - filtering: 40% (steps by filterChunk)
     *   - distinct + sort: 20%
     *   - apex grouping: 40% (steps by groupChunk)
     *
     * @param onProgress called multiple times; the sum of steps == input.size.
     */
    private fun normalizeDomains(
        input: List<String>,
        onProgress: (Int) -> Unit = {},
    ): List<String> {
        if (input.isEmpty()) return emptyList()

        val total = input.size
        val filterBudget = total * 40 / 100
        val sortBudget = total * 20 / 100
        val groupBudget = total - filterBudget - sortBudget  // remainder

        // --- Filtering ---
        val cleaned = ArrayList<String>(total)
        val filterChunk = (total / 20).coerceAtLeast(1)
        var filterDone = 0
        var stepCounter = 0

        for (d in input) {
            val norm = d.trim().lowercase()
            if (norm.isNotEmpty() &&
                norm.contains(".") &&
                !norm.matches(Regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) &&
                isRussianDomain(norm) &&
                !isMailSubdomain(norm)
            ) {
                cleaned += norm
            }
            stepCounter++
            if (stepCounter >= filterChunk && filterDone < filterBudget) {
                val step = stepCounter.coerceAtMost(filterBudget - filterDone)
                onProgress(step)
                filterDone += step
                stepCounter = 0
            }
        }
        // Account for the remainder of the filtering budget.
        if (filterDone < filterBudget) {
            onProgress(filterBudget - filterDone)
            filterDone = filterBudget
        }

        // --- distinct + sort (20%) ---
        val distinctSorted = cleaned.distinct().sorted()
        if (sortBudget > 0) {
            onProgress(sortBudget)
        } else if (filterBudget + groupBudget < total) {
            // For tiny inputs, top up the remainder.
            onProgress(total - filterBudget - groupBudget)
        }

        // --- Apex grouping pass (remainder) ---
        val result = ArrayList<String>(distinctSorted.size)
        val seenApex = HashMap<String, Int>(distinctSorted.size / 2)

        val groupChunk = (distinctSorted.size / 20).coerceAtLeast(1)
        var groupDone = 0
        var gCounter = 0

        for (domain in distinctSorted) {
            val apex = apexOf(domain)
            val count = seenApex[apex] ?: 0
            if (count < MAX_PER_APEX) {
                result += domain
                seenApex[apex] = count + 1
            }
            gCounter++
            if (gCounter >= groupChunk && groupDone < groupBudget) {
                val step = gCounter.coerceAtMost(groupBudget - groupDone)
                onProgress(step)
                groupDone += step
                gCounter = 0
            }
        }
        // Account for the remainder of the grouping budget.
        if (groupDone < groupBudget) {
            onProgress(groupBudget - groupDone)
        }

        return result
    }

    /**
     * true if the domain is in a Russian zone.
     *
     * Cyrillic zones can arrive as Unicode ("рф") or in punycode
     * ("xn--p1ai") — both variants are covered in RU_TLDS.
     */
    private fun isRussianDomain(domain: String): Boolean {
        val lastDot = domain.lastIndexOf('.')
        if (lastDot < 0 || lastDot == domain.length - 1) return false
        val tld = domain.substring(lastDot + 1)
        return tld in RU_TLDS
    }

    /**
     * true if ANY label of the domain, except the last two (apex),
     * starts with "mail".
     *
     *   "mail.example.ru"     → true  (first label "mail")
     *   "www.mail.example.ru" → true  (second label "mail")
     *   "mail2.example.ru"    → true  (first label "mail2")
     *   "mailer.example.ru"   → true  (first label "mailer")
     *   "email.example.ru"    → false (first label "email")
     *   "example.ru"          → false (no subdomain — apex)
     *   "www.example.ru"      → false (label "www")
     */
    private fun isMailSubdomain(domain: String): Boolean {
        val labels = domain.split('.')
        if (labels.size <= 2) return false
        for (i in 0 until labels.size - 2) {
            if (labels[i].startsWith("mail")) return true
        }
        return false
    }

    /**
     * Returns the apex domain for an arbitrary name.
     *
     * Simple rule: the last 2 labels, but with awareness of common
     * two-level TLDs (co.uk, com.ru, etc.).
     */
    private fun apexOf(domain: String): String {
        val labels = domain.split('.')
        if (labels.size < 2) return domain

        if (labels.size >= 3) {
            val lastTwo = "${labels[labels.size - 2]}.${labels[labels.size - 1]}"
            if (lastTwo in TWO_LEVEL_TLDS) {
                return "${labels[labels.size - 3]}.$lastTwo"
            }
        }

        return "${labels[labels.size - 2]}.${labels[labels.size - 1]}"
    }
}