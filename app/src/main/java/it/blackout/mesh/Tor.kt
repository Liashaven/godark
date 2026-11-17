package it.blackout.mesh

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.os.IBinder
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import org.json.JSONObject
import org.torproject.jni.TorService

/**
 * "Connect through Tor" (Connections screen, on by default; spec/FORMAT.md, "Tor"). Tor runs inside GoDark
 * (tor-android, the same Tor that Orbot uses), so relays don't see this phone's internet address and no other app is
 * needed. Relay links go only through its SOCKS port, and only after a check through it says traffic leaves through
 * Tor; while Tor starts, nothing goes to the relays.
 */
object Tor {
    const val CHECK_URL = "https://check.torproject.org/api/ip"

    private fun prefs(c: Context) = c.getSharedPreferences("mesh", 0)
    fun enabled(c: Context) = prefs(c).getBoolean("tor", true)
    fun setEnabled(c: Context, on: Boolean) = prefs(c).edit().putBoolean("tor", on).apply()

    @Volatile private var service: TorService? = null
    @Volatile private var on = false     // Tor said it has a circuit
    private var bound: ServiceConnection? = null
    private var receiver: BroadcastReceiver? = null

    /** Starts Tor inside the app, if it isn't running. Main thread. */
    fun start(c: Context) {
        if (bound != null) return
        val app = c.applicationContext
        receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, i: Intent) {
                on = i.getStringExtra(TorService.EXTRA_STATUS) == TorService.STATUS_ON
            }
        }.also { LocalBroadcastManager.getInstance(app).registerReceiver(it, IntentFilter(TorService.ACTION_STATUS)) }
        bound = object : ServiceConnection {
            override fun onServiceConnected(n: ComponentName, b: IBinder) { service = (b as TorService.LocalBinder).service }
            override fun onServiceDisconnected(n: ComponentName) { service = null; on = false }
        }.also { app.bindService(Intent(app, TorService::class.java), it, Context.BIND_AUTO_CREATE) }
    }

    /** Stops Tor (it stops once nothing is bound to it). Main thread. */
    fun stop(c: Context) {
        val app = c.applicationContext
        bound?.let { runCatching { app.unbindService(it) } }
        receiver?.let { LocalBroadcastManager.getInstance(app).unregisterReceiver(it) }
        bound = null; receiver = null; service = null; on = false
    }

    /** Tor's SOCKS port once it has a circuit, else null. */
    fun socksPort(): Int? = service?.socksPort?.takeIf { on && it > 0 }

    /** The Tor Project's answer: {"IsTor": true, "IP": …}. */
    fun isTor(json: String): Boolean = runCatching { JSONObject(json).getBoolean("IsTor") }.getOrDefault(false)

    /** Asks the Tor Project, through [client] (which goes through Tor), whether traffic leaves through Tor. Blocking. */
    fun check(client: okhttp3.OkHttpClient, label: String = ""): Boolean = runCatching {
        client.newCall(okhttp3.Request.Builder().url(CHECK_URL).build()).execute().use { r ->
            val body = r.peekBody(4096).string()
            DebugTools.log("tor check $label: ${runCatching { JSONObject(body).optString("IP") }.getOrDefault("?")}")
            r.isSuccessful && isTor(body)
        }
    }.onFailure { DebugTools.log("tor check $label failed: $it") }.getOrDefault(false)
}

/**
 * Connections through Tor's SOCKS port with a user name of our choosing: Tor keeps streams with different user names on
 * different circuits, so each group reaches the relays from a different exit (spec "Tor"). Java's own SOCKS can't vary
 * the name per connection. Host names go to Tor, never to the phone's resolver.
 */
object Socks5 {
    /** A made-up address that carries the host name to [Tunnel]. */
    val noDns = object : okhttp3.Dns { override fun lookup(hostname: String) = listOf(java.net.InetAddress.getByAddress(hostname, ByteArray(4))) }

    fun factory(port: Int, user: String): javax.net.SocketFactory = object : javax.net.SocketFactory() {
        override fun createSocket(): java.net.Socket = Tunnel(port, user)
        private fun no(): Nothing = throw UnsupportedOperationException("OkHttp makes unconnected sockets")
        override fun createSocket(h: String?, p: Int): java.net.Socket = no()
        override fun createSocket(h: String?, p: Int, l: java.net.InetAddress?, lp: Int): java.net.Socket = no()
        override fun createSocket(h: java.net.InetAddress?, p: Int): java.net.Socket = no()
        override fun createSocket(h: java.net.InetAddress?, p: Int, l: java.net.InetAddress?, lp: Int): java.net.Socket = no()
    }

    private class Tunnel(private val proxy: Int, private val user: String) : java.net.Socket() {
        override fun connect(to: java.net.SocketAddress, timeout: Int) {
            val a = to as java.net.InetSocketAddress
            super.connect(java.net.InetSocketAddress("127.0.0.1", proxy), timeout)
            val was = soTimeout
            soTimeout = 60_000 // building a circuit can take a while
            handshake(getInputStream(), getOutputStream(), a.hostString, a.port, user)
            soTimeout = was
        }
    }

    /** RFC 1928 with RFC 1929 user and password: asks for a connection to [host]. Throws if it is refused. */
    fun handshake(i: java.io.InputStream, o: java.io.OutputStream, host: String, port: Int, user: String) {
        val data = java.io.DataInputStream(i)
        fun read(n: Int) = ByteArray(n).also(data::readFully)
        o.write(byteArrayOf(5, 1, 2)); o.flush()
        if (!read(2).contentEquals(byteArrayOf(5, 2))) throw java.io.IOException("SOCKS: no user name method")
        val name = user.toByteArray()
        o.write(byteArrayOf(1, name.size.toByte()) + name + byteArrayOf(1, 'x'.code.toByte())); o.flush()
        if (read(2)[1] != 0.toByte()) throw java.io.IOException("SOCKS: user name refused")
        val h = host.toByteArray()
        o.write(byteArrayOf(5, 1, 0, 3, h.size.toByte()) + h + byteArrayOf((port ushr 8).toByte(), port.toByte())); o.flush()
        val r = read(4)
        if (r[1] != 0.toByte()) throw java.io.IOException("SOCKS: connection refused (${r[1]})")
        read(when (r[3].toInt()) { 1 -> 4; 4 -> 16; 3 -> read(1)[0].toInt() and 0xFF; else -> throw java.io.IOException("SOCKS: bad address type") } + 2)
    }
}
