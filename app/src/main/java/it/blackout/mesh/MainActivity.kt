package it.blackout.mesh

import android.Manifest
import android.app.NotificationManager
import android.app.StatusBarManager
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.drawable.Icon
import android.location.LocationManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/** What the screens show; [tick] changes whenever the mesh has news, so the screens read it again. */
class AppState(a: ComponentActivity) {
    private val prefs = a.getSharedPreferences("mesh", 0)
    var tick by mutableIntStateOf(0)
    var group by mutableStateOf(Groups.current(a))
    var locked by mutableStateOf(AppLock.due(a)) // "Lock GoDark" is asking
    var lockOn by mutableStateOf(AppLock.enabled(a))
    var waitingSafe by mutableStateOf(false) // the "I'm safe" shortcut waits for the unlock (MainActivity.justUnlocked)
    var name by mutableStateOf(prefs.getString("name", "") ?: "")
    var invite by mutableStateOf<SavedGroup?>(null)          // an invite link that was opened
    var shareLocation by mutableStateOf(prefs.getBoolean("shareLocation", false))
    var permissionsMissing by mutableStateOf(false) // Bluetooth: without it phones can't connect
    var locationMissing by mutableStateOf(false)    // precise location: Android needs it to find phones before Android 13
    var bluetoothOff by mutableStateOf(false)       // the phone's Bluetooth switch
    var locationOff by mutableStateOf(false)        // the phone's Location switch
    var notificationsOff by mutableStateOf(false)
    var introPermissions by mutableStateOf(false)   // setup: the short explainer before Android asks
    var tab by mutableIntStateOf(0)
    var moderated by mutableIntStateOf(0) // changes when someone is blocked or a message reported
    var sheet by mutableStateOf<Sheet?>(null)
    var everyone by mutableStateOf(false)  // Chat shows the Everyone channel
    var placesMap by mutableStateOf(false) // Places shows the map
    /** Chat drafts per channel: the group's code, or "" for Everyone. */
    val drafts = mutableStateMapOf<String, String>()
    var banner by mutableStateOf<Notifier.Alert?>(null)
    /** "Send I need help?" is asked (from Home, People, a shortcut, a tile or a notification); [helpGroup]: to which group. */
    var askHelp by mutableStateOf(false)
    var helpGroup: String? = null
    var tileHowTo by mutableStateOf(false) // how to add the tile by hand (Android 12 and older)
    fun setShareLocation(c: ComponentActivity, on: Boolean) { shareLocation = on; c.getSharedPreferences("mesh", 0).edit().putBoolean("shareLocation", on).apply() }

    /** What a new screen (after Android ended the app in the background) needs to look the same. */
    fun save(b: Bundle) {
        b.putInt("tab", tab); b.putBoolean("everyone", everyone); b.putBoolean("placesMap", placesMap)
        b.putString("sheet", sheet?.let(Sheet::save))
        b.putStringArrayList("drafts", ArrayList(drafts.flatMap { listOf(it.key, it.value) }))
        b.putBoolean("introPermissions", introPermissions)
    }
    fun restore(b: Bundle) {
        tab = b.getInt("tab"); everyone = b.getBoolean("everyone"); placesMap = b.getBoolean("placesMap")
        sheet = b.getString("sheet")?.let(Sheet::restore)
        b.getStringArrayList("drafts")?.chunked(2)?.forEach { if (it.size == 2) drafts[it[0]] = it[1] }
        introPermissions = b.getBoolean("introPermissions")
    }
}

/** Changes when a permission or a phone setting may have changed, so screens that depend on them look again. */
object Perms { var version by mutableIntStateOf(0) }

class MainActivity : ComponentActivity() {
    lateinit var state: AppState
    private val refresh: () -> Unit = { Groups.current(this)?.let { if (it != state.group) state.group = it }; state.tick++ } // a removal changes the group's code
    private val prefs get() = getSharedPreferences("mesh", 0)
    private val main = Handler(Looper.getMainLooper())
    private var shareLocationAsked = false
    private var afterCredential: (() -> Unit)? = null
    private val credential = registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == RESULT_OK) afterCredential?.invoke()
        afterCredential = null
    }

    /** Before Android 11: the phone's own unlock screen ([AppLock.ask]). */
    @Suppress("DEPRECATION")
    fun confirmCredential(title: String, ok: () -> Unit) {
        val i = getSystemService(android.app.KeyguardManager::class.java).createConfirmDeviceCredentialIntent(title, null) ?: run { ok(); return }
        afterCredential = ok; credential.launch(i)
    }

    /** With the lock on, screenshots and the recent-apps picture are blocked. */
    fun applySecure() {
        val flag = android.view.WindowManager.LayoutParams.FLAG_SECURE
        if (AppLock.enabled(this)) window.addFlags(flag) else window.clearFlags(flag)
    }

    fun setAppLock(on: Boolean) {
        AppLock.set(this, on); state.lockOn = on; applySecure()
        if (on) getSystemService(NotificationManager::class.java).cancelAll() // alerts already showing still have their text
    }
    fun lockNow() { state.locked = true; Notifier.onScreen = false; Notifier.inApp = null }
    fun unlocked() { state.locked = false; Notifier.onScreen = true; Notifier.inApp = { a -> state.banner = a } }
    /**
     * The lock screen's unlock worked: what waited for it can happen now, if it hasn't waited too long ([WaitingSafe]):
     * someone else could have tapped the shortcut and left it for the owner's next unlock.
     */
    fun justUnlocked() {
        AppLock.left(stillLocked = false); unlocked()
        val f = afterUnlock; afterUnlock = null; state.waitingSafe = false
        if (f == null) return
        if (WaitingSafe.stillWanted(afterUnlockAt, android.os.SystemClock.elapsedRealtime())) f()
        else Toast.makeText(this, "“I'm safe” wasn't sent: it waited too long for the unlock. Send it again if you still want to.", Toast.LENGTH_LONG).show()
    }
    private var afterUnlock: (() -> Unit)? = null
    private var afterUnlockAt = 0L
    /** The lock screen's "Don't send". */
    fun dropWaiting() { afterUnlock = null; state.waitingSafe = false }

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        enableEdgeToEdge(SystemBarStyle.dark(Color.TRANSPARENT), SystemBarStyle.dark(Color.TRANSPARENT))
        DebugTools.debugIntent(this, intent) // debug builds only; does nothing in release
        prefs.edit().remove("stopped").apply() // opening GoDark starts it again after "Stop GoDark"
        state = AppState(this).also { s -> b?.let(s::restore) }
        Notifier.setUp(this)
        OfflineMap.setUp(this)
        LocalAi.setUp(this)
        MeshEngine.listener = refresh
        MeshService.onStop = { finishAndRemoveTask() }
        if (state.group != null) {
            startStore()
            if (wanted.any { !granted(it) && !asked(it) } && b == null) state.introPermissions = true else check()
        }
        if (b == null) handle(intent) // a new screen after a restart already handled it
        val filter = IntentFilter().apply { addAction(BluetoothAdapter.ACTION_STATE_CHANGED); addAction(LocationManager.PROVIDERS_CHANGED_ACTION) }
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(phoneSettings, filter, RECEIVER_NOT_EXPORTED) else registerReceiver(phoneSettings, filter) // system broadcasts only
        updatePhoneSettings()
        applySecure()
        setContent { GoDarkApp(state, this) }
    }

    override fun onSaveInstanceState(b: Bundle) { super.onSaveInstanceState(b); state.save(b) }

    override fun onNewIntent(i: Intent) {
        super.onNewIntent(i)
        DebugTools.debugIntent(this, i)
        handle(i)
    }

    /** An invite link, an app shortcut, a tile or a notification. Then forgotten, so a new screen doesn't act on it again. */
    private fun handle(i: Intent?) {
        if (i == null) return
        link(i)
        val group = i.getStringExtra(Actions.EXTRA_GROUP)
        if (state.group != null && i.component?.className == Actions.ALIAS) when (i.action) { // never from another app
            Actions.SAFE -> { val send = { whenReady { checkIn(this, state, CheckIn.SAFE) } }
                if (state.locked) { afterUnlock = send; afterUnlockAt = android.os.SystemClock.elapsedRealtime(); state.waitingSafe = true } else send() }
            Actions.HELP -> { showGroup(group); state.sheet = null; state.helpGroup = group; state.askHelp = true }
            Actions.CHAT -> { showGroup(group); state.sheet = null; state.everyone = false; state.tab = 1 }
        }
        i.getIntExtra(AnswerReceiver.NOTIFICATION, 0).takeIf { it != 0 }?.let { getSystemService(NotificationManager::class.java).cancel(it) }
        setIntent(Intent())
    }

    /** Accepts the established darkproof:// URI and previously created web invite URLs for compatibility. */
    private fun link(i: Intent) {
        val g = i.data?.toString()?.let(Groups::readInvite) ?: return
        if (g.code != state.group?.code) state.invite = g // with the admins it names: kept only if the user says Join
    }

    /** Shows the saved group [code] (from a notification), if it isn't shown already. */
    private fun showGroup(code: String?) {
        val g = Groups.find(this, code) ?: return
        if (g.code != state.group?.code) switchTo(g)
    }

    /** Runs [f] once the message store is open (a shortcut can arrive while GoDark is still starting). */
    private fun whenReady(tries: Int = 40, f: () -> Unit) {
        if (MeshEngine.router != null) f() else if (tries > 0) main.postDelayed({ whenReady(tries - 1, f) }, 250)
    }

    override fun onStart() { super.onStart(); if (AppLock.due(this)) state.locked = true }
    override fun onStop() { if (!isChangingConfigurations) AppLock.left(state.locked); super.onStop() }

    override fun onResume() {
        super.onResume()
        if (!state.locked) unlocked() // while locked, alerts go out as notifications, without their text
        updatePhoneSettings()
        if (state.group != null && !state.introPermissions) check() // back from Settings
    }

    /** Opens the message store and the group's keys at once, so messages written before the mesh is up are kept. */
    private fun startStore() {
        val g = state.group ?: return; val name = state.name
        Thread { MeshEngine.start(applicationContext, name, g.code) }.start()
    }
    override fun onPause() { Notifier.onScreen = false; Notifier.inApp = null; super.onPause() }

    /** After the first setup: saves the group and starts the mesh; Android asks for permissions after a short explainer. */
    fun started(name: String, g: SavedGroup) {
        Groups.setUp(this, name, g)
        state.name = name; state.group = g
        startStore()
        if (wanted.all(::granted)) check() else state.introPermissions = true
    }

    fun switchTo(g: SavedGroup) { Groups.switchTo(this, g); state.group = g; state.tick++ }

    // MARK: - Permissions

    private fun granted(p: String) = checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED
    private fun asked(p: String) = prefs.getBoolean("asked.$p", false)

    /** Without these the Bluetooth code would crash, so the mesh starts only with them (Android 12+). */
    private val bluetooth = if (Build.VERSION.SDK_INT >= 31)
        listOf(Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_SCAN) else emptyList()
    private val nearbyWifi = if (Build.VERSION.SDK_INT >= 33) listOf(Manifest.permission.NEARBY_WIFI_DEVICES) else emptyList()
    /** Fine and coarse together, as Android 12+ requires. */
    private val location = listOf(Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.ACCESS_FINE_LOCATION)
    private val notifications = if (Build.VERSION.SDK_INT >= 33) listOf(Manifest.permission.POST_NOTIFICATIONS) else emptyList()
    private val wanted get() = bluetooth + nearbyWifi + notifications + location

    /**
     * Asks Android for what is missing of [perms]; once someone said "Don't allow" twice Android doesn't ask any more,
     * so then the app's settings page opens instead. False if nothing was missing.
     */
    private fun ask(perms: List<String>, code: Int): Boolean {
        val need = perms.filterNot(::granted)
        if (need.isEmpty()) return false
        if (need.any { !asked(it) || shouldShowRequestPermissionRationale(it) }) {
            prefs.edit().apply { need.forEach { putBoolean("asked.$it", true) } }.apply()
            requestPermissions(need.toTypedArray(), code)
        } else openAppSettings()
        return true
    }

    /** "Continue" on the setup explainer: Android asks for everything at once. */
    fun permissions() { state.introPermissions = false; if (!ask(wanted, 1)) check() }
    /** Home and Connections: Nearby devices (and location, which Nearby needs on some phones). */
    fun askNearby() { if (!ask(bluetooth + nearbyWifi + location, 1)) check() }
    fun askLocation() { ask(location, 3) }
    fun askNotifications() { if (!ask(notifications, 2) && state.notificationsOff) openAppSettings() }
    /** "Share my location": turns on once location is allowed. */
    fun shareLocation(on: Boolean) {
        state.setShareLocation(this, on)
        if (on && !Locator.allowed(this)) { shareLocationAsked = true; askLocation() }
    }

    @Deprecated("Deprecated in Java")
    override fun onRequestPermissionsResult(r: Int, p: Array<String>, g: IntArray) {
        super.onRequestPermissionsResult(r, p, g)
        check() // reads the real state: a cancelled request returns empty arrays
        updatePhoneSettings()
        if (r == 3 && shareLocationAsked && !Locator.allowed(this)) state.setShareLocation(this, false)
        shareLocationAsked = false
    }

    /** Starts the mesh when Bluetooth is allowed; without precise location it still runs, with fewer ways to find phones. */
    private fun check() {
        state.permissionsMissing = !bluetooth.all(::granted)
        state.locationMissing = !granted(Manifest.permission.ACCESS_FINE_LOCATION)
        if (!state.permissionsMissing) launch()
    }

    private fun launch() {
        if (state.group == null) return
        MeshService.start(this)
        state.tick++
    }

    // MARK: - Phone settings

    private val phoneSettings = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) = updatePhoneSettings()
    }

    private fun updatePhoneSettings() {
        state.bluetoothOff = getSystemService(BluetoothManager::class.java)?.adapter?.isEnabled == false
        state.locationOff = !Locator.enabled(this)
        state.notificationsOff = !getSystemService(NotificationManager::class.java).areNotificationsEnabled() ||
            (notifications.isNotEmpty() && !notifications.all(::granted))
        Perms.version++
    }

    fun openAppSettings() = runCatching { startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null))) }

    /** Android's "Turn on Bluetooth?" question (it needs the Nearby devices permission first, checked here). */
    @android.annotation.SuppressLint("MissingPermission")
    fun turnOnBluetooth() {
        if (Build.VERSION.SDK_INT >= 31 && !granted(Manifest.permission.BLUETOOTH_CONNECT)) { askNearby(); return }
        runCatching { startActivity(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)) }
            .onFailure { runCatching { startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS)) } }
    }

    fun openLocationSettings() = runCatching { startActivity(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS)) }

    /** "Get ready": adds the "I'm safe" tile with Android's own question (Android 13+), else explains how. */
    fun addTile() {
        if (Build.VERSION.SDK_INT >= 33) runCatching {
            getSystemService(StatusBarManager::class.java).requestAddTileService(ComponentName(this, SafeTile::class.java), getString(R.string.tile_safe),
                Icon.createWithResource(this, R.drawable.ic_verified_user), mainExecutor) { r ->
                if (r == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ADDED || r == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ALREADY_ADDED) Ready.mark(this, Ready.TILE)
                state.tick++
            }
        }.onFailure { state.tileHowTo = true }
        else state.tileHowTo = true
    }

    fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_LONG).show()

    // A new screen can start before the old one is destroyed: only unhook our own listener.
    override fun onDestroy() {
        if (MeshEngine.listener === refresh) MeshEngine.listener = null
        MeshService.onStop = null
        runCatching { unregisterReceiver(phoneSettings) }
        super.onDestroy()
    }
}
