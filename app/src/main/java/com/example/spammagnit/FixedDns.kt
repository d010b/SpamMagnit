package com.example.spammagnit

import okhttp3.Dns
import java.net.InetAddress

/**
 * Custom OkHttp Dns that resolves a hostname to a predefined IP
 * instead of using the system resolver. Falls back to the system
 * resolver if the hostname is not in the map.
 */
class FixedDns(private val ipByHost: Map<String, String>) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        val ip = ipByHost[hostname] ?: ipByHost[hostname.lowercase()]
        return if (ip != null) {
            listOf(InetAddress.getByName(ip))
        } else {
            Dns.SYSTEM.lookup(hostname)
        }
    }
}