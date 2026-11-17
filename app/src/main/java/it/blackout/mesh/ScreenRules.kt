package it.blackout.mesh

import java.net.Inet4Address
import java.net.InetAddress

// Small rules the screens and the Wi-Fi board follow, kept apart from them so unit tests run: plain Kotlin, no Android
// dependencies. What the assistant is given is in Protocol.kt (AiContext).

/** Cutting text other people wrote. */
object Cut {
    /**
     * The start of [s], at most [max] UTF-16 units and never half a character: a cut inside a surrogate pair (an emoji)
     * leaves a broken string, which code outside the JVM, like the map's and the AI's, may not survive.
     */
    fun units(s: String, max: Int): String =
        if (s.length <= max) s else s.take(max.coerceAtLeast(0)).let { if (it.isNotEmpty() && it.last().isHighSurrogate()) it.dropLast(1) else it }
}

/** How long a message alert stays (spec "Alerts"). */
object AlertLife {
    const val WEEK_MS = 7 * 24 * 3_600_000L

    /**
     * The timeout of an alert for a message dated [ts], posted at [now]: it goes a week after the message's date, before
     * the phone can delete the message itself, so its text doesn't outlive the message. A minute at least, for a message
     * that arrives that late; a week at most, for one dated ahead.
     */
    fun timeout(ts: Long, now: Long): Long = (ts + WEEK_MS - now).coerceIn(60_000L, WEEK_MS)
}

/**
 * Keys for the rows of a list. A lazy list ends the app when two of its rows have the same key, so a key that was given
 * out before comes back with "#2", "#3"…: the same rows in the same order always get the same keys. One per list;
 * not thread-safe.
 */
class RowKeys {
    private val used = HashSet<String>()
    fun unique(key: String): String {
        var k = key; var n = 1
        while (!used.add(k)) k = "$key#${++n}"
        return k
    }
}

/** Who the Wi-Fi board (WifiBoard.kt) serves. */
object BoardRules {
    /** Network interfaces that are not the Wi-Fi around this phone: mobile data and VPNs. */
    private val FAR_IFACES = listOf("rmnet", "ccmni", "dummy", "tun", "ppp", "wwan", "ipsec")

    /**
     * The first look at a caller, before it takes a place: an IPv4 address of a local network. The board is only ever
     * opened by its IPv4 address, and IPv6 link-local addresses are ones a caller makes up as many of as it likes.
     */
    fun mayEnter(peer: InetAddress?): Boolean = peer is Inet4Address && (peer.isSiteLocalAddress || peer.isLinkLocalAddress)

    /**
     * True if a caller is on the Wi-Fi around this phone: the board is for people who joined its Wi-Fi network or share
     * one with it, not for the mobile network, a VPN, or other apps on this phone. The kind of address a caller has
     * doesn't say that: an app on this phone that calls the phone's own Wi-Fi address has such an address, and so has
     * a stranger on a mobile or VPN network that hands out private addresses. So: [peer], the caller, is none of this
     * phone's [own] addresses; [local], the address of this phone it reached, is on an interface ([iface]) that isn't
     * mobile data or a VPN; and the caller is in that address's own network (its first [prefix] bits).
     * Anything that can't be told (no interface, no prefix) is not nearby.
     */
    fun nearby(peer: InetAddress?, local: InetAddress?, prefix: Int, iface: String?, own: Collection<InetAddress>): Boolean {
        if (!mayEnter(peer) || peer == null || peer in own) return false
        if (local !is Inet4Address || iface == null || FAR_IFACES.any { iface.startsWith(it) }) return false
        if (prefix !in 1..30) return false // 31 and 32 are point-to-point links, like mobile data
        val a = peer.address; val b = local.address
        return (0 until prefix).all { i -> (a[i / 8].toInt() shr (7 - i % 8)) and 1 == (b[i / 8].toInt() shr (7 - i % 8)) and 1 }
    }
}

/**
 * How many of the board's places one visitor holds at a time, by address: connections, and app downloads, which may
 * hold a worker for minutes. Without it one visitor could hold them all and nobody else got an answer. Only visitors
 * holding a place are remembered. Thread-safe.
 */
class BoardDoor(private val perClient: Int, private val inAll: Int = Int.MAX_VALUE) {
    private val held = HashMap<String, Int>()
    private var total = 0

    /** Takes a place for [client]; false if it holds its share already, or all are taken. Each true needs one [leave]. */
    @Synchronized fun enter(client: String): Boolean {
        val n = held[client] ?: 0
        if (n >= perClient || total >= inAll) return false
        held[client] = n + 1; total++
        return true
    }

    @Synchronized fun leave(client: String) {
        val n = held[client] ?: return
        if (n > 1) held[client] = n - 1 else held.remove(client)
        total--
    }

    /** Visitors holding a place now. */
    val clients: Int @Synchronized get() = held.size
}

/**
 * Which posts the board takes. They go worldwide under this phone's key, so: at most [perMinute] in any minute from
 * everyone together; at most [perClient] of those from one address, so one visitor can't use up everyone's; and
 * [gapMs] between two posts from one address. Only posts that were taken are remembered, and only for a minute, so
 * what is kept never grows past [perMinute] entries, however many addresses ask. Thread-safe.
 */
class BoardPosts(private val gapMs: Long, private val perMinute: Int, private val perClient: Int) {
    enum class Answer { TAKEN, WAIT, SHARE_USED, FULL }

    private val taken = ArrayDeque<Pair<Long, String>>() // time and address of each post of the last minute, oldest first

    @Synchronized fun ask(client: String, now: Long): Answer {
        taken.removeAll { now - it.first !in 0 until 60_000 } // over a minute old, or dated ahead because the clock was set back
        val mine = taken.filter { it.second == client }
        return when {
            mine.any { now - it.first < gapMs } -> Answer.WAIT
            mine.size >= perClient -> Answer.SHARE_USED
            taken.size >= perMinute -> Answer.FULL
            else -> { taken.addLast(now to client); Answer.TAKEN }
        }
    }

    /** Posts remembered now. */
    val remembered: Int @Synchronized get() = taken.size
}
