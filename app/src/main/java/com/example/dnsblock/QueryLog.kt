package com.example.dnsblock

import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicInteger

object QueryLog {
    data class Entry(val name: String, val blocked: Boolean)
    private val q = ConcurrentLinkedDeque<Entry>()
    val version = AtomicInteger()
    fun add(name: String, blocked: Boolean) {
        q.addFirst(Entry(name, blocked))
        while (q.size > 200) q.pollLast()
        version.incrementAndGet()
    }
    fun snapshot(): List<Entry> = q.toList()
}
