package com.example.spammagnit

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

class DomainChecker(fixedDns: FixedDns) {

    private val client: OkHttpClient = run {
        // Trust-all X509 manager: we only check reachability,
        // not certificate validity.
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustAll), SecureRandom())
        }

        OkHttpClient.Builder()
            .dns(fixedDns)
            .sslSocketFactory(sslContext.socketFactory, trustAll)
            .hostnameVerifier { _, _ -> true }
            .connectTimeout(4, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .writeTimeout(4, TimeUnit.SECONDS)
            .callTimeout(8, TimeUnit.SECONDS)
            .followRedirects(true)
            .followSslRedirects(true)
            .retryOnConnectionFailure(false)
            .build()
    }

    suspend fun check(domain: String, ip: String): CheckResult =
        withContext(Dispatchers.IO) {
            val start = System.nanoTime()

            // Try HTTPS first.
            val https = tryGet("https://$domain/")
            if (https != null) {
                return@withContext CheckResult(
                    domain = domain,
                    ip = ip,
                    status = Status.OK_HTTPS,
                    httpCode = https.code,
                    bodySize = https.size,
                    elapsedMs = (System.nanoTime() - start) / 1_000_000,
                    error = null,
                )
            }

            // Fall back to plain HTTP.
            val http = tryGet("http://$domain/")
            if (http != null) {
                return@withContext CheckResult(
                    domain = domain,
                    ip = ip,
                    status = Status.OK_HTTP,
                    httpCode = http.code,
                    bodySize = http.size,
                    elapsedMs = (System.nanoTime() - start) / 1_000_000,
                    error = null,
                )
            }

            // Both protocols failed.
            CheckResult(
                domain = domain,
                ip = ip,
                status = Status.FAIL,
                httpCode = null,
                bodySize = 0,
                elapsedMs = (System.nanoTime() - start) / 1_000_000,
                error = "https+http failed",
            )
        }

    private data class SimpleResult(val code: Int, val size: Long)

    /**
     * Performs a single GET request and returns the response code
     * plus the number of bytes actually read (capped at 16 KB).
     * Returns null on any exception.
     */
    private fun tryGet(url: String): SimpleResult? = try {
        val req = Request.Builder()
            .url(url)
            .header("User-Agent", "Mozilla/5.0 (Linux; Android 13)")
            .header("Accept", "*/*")
            .header("Range", "bytes=0-16383")
            .build()

        client.newCall(req).execute().use { resp ->
            var total = 0L
            val body = resp.body
            if (body != null) {
                val buf = ByteArray(8 * 1024)
                body.byteStream().use { ins ->
                    // Read at most 16 KB to avoid downloading huge bodies.
                    while (total < 16 * 1024) {
                        val n = ins.read(buf)
                        if (n <= 0) break
                        total += n
                    }
                }
            }
            SimpleResult(resp.code, total)
        }
    } catch (e: Exception) {
        null
    }
}