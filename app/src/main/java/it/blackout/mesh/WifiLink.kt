package it.blackout.mesh

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Handler
import android.os.Looper
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * TCP links to GoDark phones on the same Wi-Fi network (spec/FORMAT.md, "Wi-Fi networks"). Plain Java sockets, so
 * unit tests run it on a computer; [WifiLink] adds Android's network service discovery on top.
 */
class WifiLinks(private val nodeId: String, private val router: () -> MeshRouter?, private val changed: () -> Unit,
                /** Whether an address is on the local network ([onLan] in the app; unit tests link over loopback). */
                private val local: (java.net.InetAddress) -> Boolean = { true }) {
    companion object {
        const val PREFIX = "wifi:"
        const val PORT = 7777
        const val MAX_FRAME = 16_064
        const val MAX_LINKS = 32
        private const val MAX_QUEUED_LINK = 12L * 1024 * 1024 // waiting to go out to one phone; more means it stopped reading
        private const val MAX_QUEUED_ALL = 32L * 1024 * 1024
        private const val RETRY_MS = 5_000L
        const val HELLO_WAIT_MS = 10_000      // the other side's HELLO must come within this
        private val HELLO = "DPW1".toByteArray()
        fun owns(peer: String) = peer.startsWith(PREFIX)
        /**
         * On a network this phone is on (spec/FORMAT.md, "Wi-Fi networks": nothing leaves that network): a private or
         * link-local address, or one in the subnet of one of this phone's own addresses. Not loopback, and not a host
         * out on the internet, whatever a DNS-SD answer says.
         */
        fun onLan(a: java.net.InetAddress): Boolean {
            if (LinkLimits.local(a.address)) return true
            if (a.isLoopbackAddress || a.isAnyLocalAddress) return false
            return try {
                java.net.NetworkInterface.getNetworkInterfaces()?.asSequence().orEmpty().filter { it.isUp && !it.isLoopback }
                    .flatMap { it.interfaceAddresses.asSequence() }
                    .any { i -> i?.address?.address?.let { sameNet(it, a.address, i.networkPrefixLength.toInt()) } == true }
            } catch (_: IOException) { false }
        }
        private fun sameNet(x: ByteArray, y: ByteArray, bits: Int): Boolean {
            if (x.size != y.size || bits <= 0 || bits > x.size * 8) return false
            return (0 until bits).all { (x[it / 8].toInt() xor y[it / 8].toInt()) and (0x80 shr (it % 8)) == 0 }
        }
    }

    /** [dialed]: this phone opened the connection. [since]: when the HELLOs were exchanged. */
    private class Link(val id: String, val node: String, val socket: Socket, val out: DataOutputStream, val dialed: Boolean) {
        val writer = Executors.newSingleThreadExecutor()
        val since = System.currentTimeMillis()
        var queued = 0L      // bytes waiting to go out to it; guarded by `queues`
        var cut = false      // closed for what was waiting: that is off the total already; guarded by `queues`
    }
    private val queues = Any()
    private var queuedAll = 0L // guarded by `queues`
    private val slots = java.util.concurrent.Semaphore(MAX_LINKS + LinkLimits.WAITING) // connections being served, so they can't use up threads
    private val waiting = LinkedHashMap<Socket, String>() // connections that dialed in and haven't said HELLO yet -> address, oldest first
    private val stops = AtomicInteger()                   // counts stop(): a connection begun before the last one never becomes a link
    @Volatile private var stopped = false
    private var rotatedAt = 0L                            // guarded by `byNode`
    private val watchdog = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "wifi-watchdog").apply { isDaemon = true } }
    private val links = ConcurrentHashMap<String, Link>()   // router peer id -> link
    private val byNode = ConcurrentHashMap<String, Link>()  // node id -> its current link
    private val sockets = ConcurrentHashMap.newKeySet<Socket>()
    private val count = AtomicInteger()
    private val dialing = ConcurrentHashMap.newKeySet<String>()
    private val listening = AtomicBoolean()
    private val manualGen = AtomicInteger()
    @Volatile private var server: ServerSocket? = null
    @Volatile var manual: String? = null; private set   // "host:port" the user typed
    @Volatile var note = ""; private set

    val port get() = server?.localPort ?: 0
    fun linkCount() = links.size
    fun nodes(): Set<String> = byNode.keys.toSet()

    /**
     * For deciding whether to dial [host]: [node] counts as linked only through a link whose other end is that address.
     * A node id in a HELLO proves nothing (spec/FORMAT.md, "Node ids prove nothing"), so a link from elsewhere that
     * only claims a phone's id must not stop this phone from dialing the real one.
     */
    fun linkedAt(node: String, host: String): Boolean {
        val a = try { java.net.InetAddress.getByName(host) } catch (_: IOException) { return false }
        return links.values.any { it.node == node && it.socket.inetAddress == a }
    }

    /** Listens on 7777, or any free port if it is taken. Returns the port, or 0 if listening failed. */
    fun listen(preferred: Int = PORT): Int {
        if (!listening.compareAndSet(false, true)) return port
        stopped = false; val gen = stops.get()
        val ss = try { bind(preferred) } catch (_: IOException) {
            try { bind(0) } catch (e: IOException) { listening.set(false); update("can't open a connection on this network"); return 0 }
        }
        server = ss
        thread(isDaemon = true, name = "wifi-listen") {
            try { while (true) { val s = ss.accept()
                if (!local(s.inetAddress) || !slots.tryAcquire()) { quiet(s); continue } // only from the local network
                admit(s)
                thread(isDaemon = true, name = "wifi-in") { try { serve(s, dialed = false, gen) } finally { slots.release() } } } }
            catch (_: IOException) { } finally { quiet(ss); server = null; listening.set(false); changed() }
        }
        return ss.localPort
    }
    private fun bind(port: Int) = ServerSocket().apply { reuseAddress = true; bind(InetSocketAddress(port)) }

    /**
     * A connection that dialed in waits for its HELLO. At most 16 wait, 4 of them from one address: over that, one
     * that is still waiting gives way (that address's oldest, else the oldest of the address with the most, else the
     * oldest of all), so connections that say nothing can't keep real phones out.
     */
    private fun admit(s: Socket) {
        val a = s.inetAddress?.hostAddress ?: ""
        val gone = synchronized(waiting) {
            val i = when (val g = LinkLimits.giveWay(waiting.values.toList(), a, LinkLimits.WAITING, LinkLimits.WAITING_PER_ADDRESS)) {
                LinkLimits.ROOM -> -1; LinkLimits.FULL -> 0; else -> g
            }
            (if (i >= 0) waiting.keys.elementAt(i).also { waiting.remove(it) } else null).also { waiting[s] = a }
        }
        gone?.let(::quiet)
    }

    /**
     * One attempt to link to a discovered device: only at an address on the local network (a DNS-SD answer can name
     * any host), and at most 8 attempts at once.
     */
    fun dial(host: String, port: Int) {
        if (stopped) return
        val gen = stops.get()
        val at = try { java.net.InetAddress.getByName(host) } catch (_: IOException) { return }
        if (!local(at)) return
        val key = "$host:$port"
        if (dialing.size >= LinkLimits.DIALS || !dialing.add(key)) return
        thread(isDaemon = true, name = "wifi-dial") {
            val s = Socket()
            try { s.connect(InetSocketAddress(at, port), 5_000); serve(s, dialed = true, gen) } catch (_: IOException) { quiet(s) }
            finally { dialing.remove(key) }
        }
    }

    /**
     * Keeps a link to an address the user typed, redialing every 5 s, until [stopManual] or another address. While the
     * phone at that address is linked another way (it dialed this phone from that address), it isn't dialed again.
     */
    fun connectManually(host: String, port: Int) {
        val gen = manualGen.incrementAndGet()
        stopped = false; val since = stops.get()
        manual = "$host:$port"; update("")
        thread(isDaemon = true, name = "wifi-manual") {
            var node: String? = null // who answered at that address last time
            while (manualGen.get() == gen) {
                val n = node
                if (n == null || !linkedAt(n, host)) { // a link from another address that claims its id doesn't count
                    val s = Socket()
                    try { s.connect(InetSocketAddress(host, port), RETRY_MS.toInt()); if (manualGen.get() == gen) serve(s, dialed = true, since) { node = it } else quiet(s) }
                    catch (e: IOException) { quiet(s); if (manualGen.get() == gen) update("can't reach $host:$port, retrying") }
                }
                if (manualGen.get() == gen) Thread.sleep(RETRY_MS)
            }
        }
    }

    fun stopManual() { manualGen.incrementAndGet(); manual = null; update("") }

    /** Closes every link and every connection still being made: one that completes afterwards is closed too. */
    fun stop() {
        stopped = true; stops.incrementAndGet()
        stopManual()
        server?.let(::quiet)
        sockets.forEach(::quiet)
        update("")
    }

    /**
     * A place for one more link from [from]. One address holds at most 8: its own oldest makes room. With every place
     * taken, the address that holds the most gives up its oldest. If nobody holds more than one, a link at random
     * gives way, at most once in 30 s and whatever its age, so nobody can hold every place: not by just staying, and
     * not by making its links anew to keep them young.
     */
    private fun makeRoom(from: java.net.InetAddress): Boolean {
        val all = links.values.sortedBy { it.since }
        val l = when (val i = LinkLimits.giveWay(all.map { it.socket.inetAddress?.hostAddress ?: "" }, from.hostAddress ?: "", MAX_LINKS, LinkLimits.PER_ADDRESS)) {
            LinkLimits.ROOM -> return true
            LinkLimits.FULL -> {
                val now = System.currentTimeMillis()
                if (now - rotatedAt < LinkLimits.ROTATE_MS) return false
                rotatedAt = now; all.randomOrNull() ?: return false
            }
            else -> all[i]
        }
        links.remove(l.id); quiet(l.socket)
        return true
    }

    /** Called by the router, possibly while it holds its lock: the write happens on the link's own thread. */
    fun send(peer: String, p: Packet) {
        val l = links[peer] ?: return
        val b = p.encode(); val n = b.size.toLong()
        // A phone that stopped reading: what is waiting for it would pile up here until the app ran out of memory. When
        // all links together have too much waiting, the links that hold the most are closed, not the one this packet
        // is for: that one may be reading as it should.
        val closed = ArrayList<Link>()
        synchronized(queues) {
            if (l.cut) return
            if (l.queued + n > MAX_QUEUED_LINK) closed += cut(l)
            while (!l.cut && queuedAll + n > MAX_QUEUED_ALL) closed += cut(links.values.filter { !it.cut }.maxByOrNull { it.queued } ?: break)
            if (!l.cut) { l.queued += n; queuedAll += n }
        }
        closed.forEach { quiet(it.socket) }
        if (l in closed) return
        fun done() { synchronized(queues) { if (!l.cut) { l.queued -= n; queuedAll -= n } } }
        try {
            l.writer.execute { try { l.out.writeInt(b.size); l.out.write(b); l.out.flush() } catch (_: IOException) { quiet(l.socket) } finally { done() } }
        } catch (_: RejectedExecutionException) { done() } // link already closed
    }

    /** Hold `queues`. What was waiting for [l] no longer counts: the link is being closed. */
    private fun cut(l: Link): Link { l.cut = true; queuedAll -= l.queued; l.queued = 0; return l }

    /**
     * Runs one link until it drops: HELLO both ways, then packets. Blocks the calling thread. [dialed]: this phone
     * opened it. [gen]: [stops] when the connection was begun. [hello] gets the other side's node id.
     */
    private fun serve(s: Socket, dialed: Boolean, gen: Int, hello: (String) -> Unit = {}) {
        val r = router() ?: run { synchronized(waiting) { waiting.remove(s) }; quiet(s); return }
        sockets += s
        var link: Link? = null
        // The whole HELLO must come in this time: the socket timeout alone lets one byte every few seconds go on for minutes.
        val helloCut = watchdog.schedule({ if (link == null) quiet(s) }, HELLO_WAIT_MS.toLong(), java.util.concurrent.TimeUnit.MILLISECONDS)
        try {
            if (stops.get() != gen) return // the links were stopped while this connection was being made
            s.tcpNoDelay = true; s.soTimeout = HELLO_WAIT_MS // the HELLO must come quickly
            val out = DataOutputStream(BufferedOutputStream(s.getOutputStream()))
            val hello = HELLO + nodeId.toByteArray(Charsets.UTF_8)
            out.writeInt(hello.size); out.write(hello); out.flush()
            val inp = DataInputStream(BufferedInputStream(s.getInputStream()))
            val n = inp.readInt()
            if (n !in HELLO.size + 1..HELLO.size + 64) return
            val b = ByteArray(n).also(inp::readFully)
            if (!b.copyOf(HELLO.size).contentEquals(HELLO)) return
            val node = String(b, HELLO.size, n - HELLO.size, Charsets.UTF_8)
            if (node == nodeId) return
            synchronized(waiting) { waiting.remove(s) }
            hello(node)
            s.soTimeout = 0
            val l = Link(PREFIX + node + "#" + count.incrementAndGet(), node, s, out, dialed)
            synchronized(byNode) {
                if (stops.get() != gen) return
                val old = byNode[node]
                // Node ids aren't proof of anything: from another address this may be someone pretending, so the link
                // that's there stays and this one runs beside it (the router sees each packet once).
                val samePhone = old == null || old.socket.inetAddress == s.inetAddress
                // spec "Restarts and duplicate links": both phones keep the same link
                if (old != null && samePhone && !DuplicateLinks.keepNew(nodeId, node, dialed, old.dialed, l.since - old.since)) return
                if (!(old != null && samePhone) && !makeRoom(s.inetAddress)) return // a link that takes another's place needs none
                link = l
                links[l.id] = l
                if (samePhone) { byNode[node] = l; old?.let { quiet(it.socket) } }
            }
            // Every link from one address counts against one allowance in the router, however many node ids it sends.
            r.peerUp(l.id, PREFIX + "@" + s.inetAddress?.hostAddress); changed()
            while (true) {
                val m = inp.readInt()
                if (m !in 1..MAX_FRAME) break
                val raw = ByteArray(m).also(inp::readFully)
                Packet.decode(raw)?.let { r.receive(l.id, it) }
            }
        } catch (_: IOException) {
        } finally {
            helloCut.cancel(false)
            synchronized(waiting) { waiting.remove(s) }
            quiet(s); sockets -= s
            link?.let { l ->
                // who stands for the node id now is settled before the link leaves `links`: nobody sees one without the other
                synchronized(byNode) {
                    if (byNode[l.node] === l) links.values.firstOrNull { it !== l && it.node == l.node }.let { if (it != null) byNode[l.node] = it else byNode.remove(l.node) }
                    links.remove(l.id)
                }
                l.writer.shutdown()
                r.peerDown(l.id); changed()
            }
        }
    }

    fun statusLine(): String {
        val parts = ArrayList<String>()
        parts += if (server == null) "off" else when (links.size) { 0 -> "no phones yet"; 1 -> "1 phone linked"; else -> "${links.size} phones linked" }
        manual?.let { parts += "address $it" }
        if (note.isNotEmpty()) parts += note
        return "Wi-Fi network: " + parts.joinToString(" · ")
    }

    private fun update(n: String) { note = n; changed() }
    private fun quiet(c: Closeable) { try { c.close() } catch (_: IOException) { } }
}

/**
 * GoDark phones on the same Wi-Fi network, found with network service discovery (Bonjour/mDNS) and linked with
 * [WifiLinks]. Only the phone with the smaller node id connects, and it tries again every 10 s while unlinked.
 */
class WifiLink(c: Context, private val nodeId: String, router: () -> MeshRouter?, changed: () -> Unit) {
    companion object { const val SERVICE = "_darkproof._tcp" }
    // Debug builds also take the phone's own loopback: `adb forward` in the emulator test (README) comes in that way.
    private val debug = (c.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
    val links = WifiLinks(nodeId, router, changed) { WifiLinks.onLan(it) || (debug && it.isLoopbackAddress) }
    private val nsd = c.getSystemService(NsdManager::class.java)
    private val h = Handler(Looper.getMainLooper())
    private val found = HashMap<String, Pair<String, Int>>() // node id -> host, port (main thread)
    private val toResolve = ArrayDeque<NsdServiceInfo>()
    private var resolving = false
    private var registration: NsdManager.RegistrationListener? = null
    private var discovery: NsdManager.DiscoveryListener? = null
    var running = false; private set

    fun start() {
        if (running) return
        running = true
        val port = links.listen()
        if (port == 0) return
        registration = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(info: NsdServiceInfo) {}
            override fun onRegistrationFailed(info: NsdServiceInfo, code: Int) {}
            override fun onServiceUnregistered(info: NsdServiceInfo) {}
            override fun onUnregistrationFailed(info: NsdServiceInfo, code: Int) {}
        }.also { nsd.registerService(NsdServiceInfo().apply { serviceName = nodeId; serviceType = SERVICE; this.port = port }, NsdManager.PROTOCOL_DNS_SD, it) }
        discovery = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(type: String) {}
            override fun onDiscoveryStopped(type: String) {}
            override fun onStartDiscoveryFailed(type: String, code: Int) {}
            override fun onStopDiscoveryFailed(type: String, code: Int) {}
            // A device can announce any number of names: only so many wait to be resolved, or are remembered.
            override fun onServiceFound(info: NsdServiceInfo) = h.post { if (wanted(info.serviceName) && toResolve.size < LinkLimits.FOUND) { toResolve += info; resolveNext() } }.let { }
            override fun onServiceLost(info: NsdServiceInfo) = h.post { found.remove(info.serviceName) }.let { }
        }.also { nsd.discoverServices(SERVICE, NsdManager.PROTOCOL_DNS_SD, it) }
        h.postDelayed(::retry, 10_000)
    }

    fun stop() {
        if (!running) return
        running = false
        h.removeCallbacksAndMessages(null)
        registration?.let { runCatching { nsd.unregisterService(it) } }; registration = null
        discovery?.let { runCatching { nsd.stopServiceDiscovery(it) } }; discovery = null
        found.clear(); toResolve.clear(); resolving = false
        links.stop()
    }

    /** Only the smaller node id connects (spec), and not to itself. */
    private fun wanted(node: String) = node != nodeId && nodeId < node

    @Suppress("DEPRECATION") // resolveService: its replacement needs Android 14
    private fun resolveNext() {
        if (resolving || !running) return
        val info = toResolve.removeFirstOrNull() ?: return
        resolving = true
        nsd.resolveService(info, object : NsdManager.ResolveListener {
            override fun onResolveFailed(i: NsdServiceInfo, code: Int) = h.post { resolving = false; resolveNext() }.let { }
            override fun onServiceResolved(i: NsdServiceInfo) = h.post {
                resolving = false
                val host = i.host?.hostAddress
                if (host != null && running && (found.size < LinkLimits.FOUND || i.serviceName in found)) { found[i.serviceName] = host to i.port; links.dial(host, i.port) }
                resolveNext()
            }.let { }
        })
    }

    /**
     * Every 10 s, dials the devices it found that have no link (a link can drop while the service stays visible). Only
     * a link to the address it would dial counts: one from elsewhere may only claim that phone's node id.
     */
    private fun retry() {
        if (!running) return
        // in a new order each time: only 8 are dialed at once, and it must not always be the same ones
        found.filter { (node, at) -> wanted(node) && !links.linkedAt(node, at.first) }.values.shuffled().forEach { (host, port) -> links.dial(host, port) }
        h.postDelayed(::retry, 10_000)
    }
}
