package it.blackout.mesh

import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Base64
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Dedicated account/telemetry client. It never uses mesh, message, or relay transports. */
object AccountService {
    // Intentionally blank until the user authorizes publication and selects the real public HTTPS origin.
    const val API_BASE_URL = ""
    private const val PREFS = "account_private"
    private const val TOKEN = "access_token_enc"
    private const val KEY_ALIAS = "godark.account.session.v1"
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var consentSessionReady = false

    private val diagnosticKinds = setOf("app_crash", "startup_failure", "freeze", "other")
    // The backend's usage-event enum list is not present in this repository; reject until it is verified.
    private val allowedUsageFeatures = emptySet<String>()

    data class Account(
        val id: String,
        val email: String,
        val displayName: String,
        val createdAt: String,
        val lastLoginAt: String
    )
    data class AccountSnapshot(val account: Account, val analyticsOptIn: Boolean, val diagnosticsOptIn: Boolean)
    data class Session(val account: Account, val token: String)

    fun configured(): Boolean = API_BASE_URL.startsWith("https://")

    fun storedToken(context: Context): String? = runCatching {
        val saved = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(TOKEN, null) ?: return null
        val raw = Base64.decode(saved, Base64.NO_WRAP)
        val ivLength = raw[0].toInt()
        val iv = raw.copyOfRange(1, 1 + ivLength)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        String(cipher.doFinal(raw.copyOfRange(1 + ivLength, raw.size)), Charsets.UTF_8)
    }.getOrNull()

    fun saveToken(context: Context, token: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val iv = cipher.iv
        val value = byteArrayOf(iv.size.toByte()) + iv + cipher.doFinal(token.toByteArray(Charsets.UTF_8))
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(TOKEN, Base64.encodeToString(value, Base64.NO_WRAP)).apply()
    }

    private fun clearLocalSession(context: Context) {
        consentSessionReady = false
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .remove(TOKEN).putBoolean("analyticsOptIn", false).putBoolean("diagnosticsOptIn", false).apply()
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance("AES", "AndroidKeyStore")
        generator.init(android.security.keystore.KeyGenParameterSpec.Builder(KEY_ALIAS,
            android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true).build())
        return generator.generateKey()
    }

    fun register(context: Context, email: String, displayName: String, password: String, analytics: Boolean, diagnostics: Boolean,
                 done: (Result<Session>) -> Unit) {
        val body = JSONObject().put("email", email).put("displayName", displayName).put("password", password)
            .put("termsAccepted", true).put("privacyAcknowledged", true).put("analyticsOptIn", analytics)
            .put("diagnosticsOptIn", diagnostics).put("client", "native")
        sessionRequest(context, "/api/auth/register", body, done)
    }

    fun login(context: Context, email: String, password: String, done: (Result<Session>) -> Unit) {
        sessionRequest(context, "/api/auth/login", JSONObject().put("email", email).put("password", password).put("client", "native"), done)
    }

    private fun sessionRequest(context: Context, path: String, body: JSONObject, done: (Result<Session>) -> Unit) {
        request(context, "POST", path, body, token = null) { response ->
            response.fold(onSuccess = { raw -> runCatching {
                val json = JSONObject(raw)
                val account = json.getJSONObject("account").toAccount()
                val token = json.getString("accessToken")
                consentSessionReady = false
                setConsent(context, false, false)
                saveToken(context, token)
                Result.success(Session(account, token))
            }.getOrElse { Result.failure(it) }.also(done) }, onFailure = { done(Result.failure(it)) })
        }
    }

    fun account(context: Context, done: (Result<AccountSnapshot>) -> Unit) = authenticated(context, "GET", "/api/account", null) { result ->
        val snapshot = result.mapCatching { raw ->
            val json = JSONObject(raw)
            val a = json.getJSONObject("account")
            val c = json.getJSONObject("consents")
            val value = AccountSnapshot(a.toAccount(), c.optBoolean("analyticsOptIn", false), c.optBoolean("diagnosticsOptIn", false))
            setConsent(context, value.analyticsOptIn, value.diagnosticsOptIn)
            consentSessionReady = true
            value
        }
        if (snapshot.isFailure) {
            consentSessionReady = false
            setConsent(context, false, false)
        }
        done(snapshot)
    }

    fun logout(context: Context, done: (Result<Unit>) -> Unit) = authenticated(context, "POST", "/api/auth/logout", JSONObject()) {
        clearLocalSession(context); done(it.map { Unit })
    }

    fun export(context: Context, done: (Result<String>) -> Unit) = authenticated(context, "GET", "/api/account/export", null, done)

    fun delete(context: Context, password: String, done: (Result<Unit>) -> Unit) = authenticated(context, "DELETE", "/api/account", JSONObject().put("password", password)) {
        it.map { Unit }.also { if (it.isSuccess) clearLocalSession(context) }.let(done)
    }

    fun consent(context: Context, analytics: Boolean, diagnostics: Boolean, done: (Result<Unit>) -> Unit) =
        authenticated(context, "PATCH", "/api/account/consent", JSONObject().put("analyticsOptIn", analytics).put("diagnosticsOptIn", diagnostics)) { result ->
            if (result.isSuccess) setConsent(context, analytics, diagnostics)
            done(result.map { Unit })
        }

    /** Manual, enum-only diagnostics. No crash stack, message, location, contact, or group data is read. */
    fun submitDiagnostic(context: Context, kind: String, done: (Result<Unit>) -> Unit) {
        if (!diagnosticKinds.contains(kind)) return done(Result.failure(IllegalArgumentException("Diagnostic category is not allowlisted")))
        if (!consentSessionReady || !consentEnabled(context, "diagnosticsOptIn")) return done(Result.failure(IllegalStateException("Diagnostics consent is off or not synchronized")))
        val appVersion = runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }.getOrNull().let(::normalizeAppVersion)
        val deviceModel = normalizeDeviceModel(Build.MODEL)
        val osVersion = normalizeOsVersion("Android", Build.VERSION.RELEASE)
        val signature = MessageDigest.getInstance("SHA-256").digest("manual-diagnostic:$kind".toByteArray()).joinToString("") { "%02x".format(it) }
        authenticated(context, "POST", "/api/telemetry/diagnostics", JSONObject()
            .put("platform", "android").put("appVersion", appVersion).put("deviceModel", deviceModel)
            .put("osVersion", osVersion).put("crashKind", kind).put("signatureHash", signature)) { done(it.map { Unit }) }
    }

    /** Feature identifiers only; refuse all usage events until the server enum allowlist is verified. */
    fun usageEvent(context: Context, feature: String, eventTime: String, done: (Result<Unit>) -> Unit) {
        if (!allowedUsageFeatures.contains(feature)) return done(Result.failure(IllegalArgumentException("Usage feature is not allowlisted")))
        if (!consentSessionReady || !consentEnabled(context, "analyticsOptIn")) return done(Result.failure(IllegalStateException("Analytics consent is off or not synchronized")))
        authenticated(context, "POST", "/api/telemetry/usage", JSONObject().put("feature", feature).put("eventTime", eventTime)) { done(it.map { Unit }) }
    }

    fun consentEnabled(context: Context, key: String) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(key, false)
    fun setConsent(context: Context, analytics: Boolean, diagnostics: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("analyticsOptIn", analytics).putBoolean("diagnosticsOptIn", diagnostics).apply()
    }

    private fun JSONObject.toAccount() = Account(
        getString("id"), getString("email"), getString("displayName"), optString("createdAt"), optString("lastLoginAt")
    )

    private fun normalizeAppVersion(raw: String?): String {
        val parts = raw?.trim()?.split('.') ?: emptyList()
        if (parts.size !in 2..3 || parts.any { it.isEmpty() || it.any { c -> !c.isDigit() } }) return "0.0.0"
        return (parts + if (parts.size == 2) listOf("0") else emptyList()).joinToString(".")
    }

    private fun normalizeDeviceModel(raw: String?): String = raw.orEmpty()
        .replace(Regex("\\s+"), "-")
        .replace(Regex("[^A-Za-z0-9.,_-]"), "")
        .take(80).ifBlank { "unknown" }

    private fun normalizeOsVersion(platform: String, raw: String?): String {
        val version = raw?.trim()?.takeIf { it.matches(Regex("[0-9]+(?:\\.[0-9]+)*")) } ?: "0"
        return "$platform-$version"
    }

    private fun authenticated(context: Context, method: String, path: String, body: JSONObject?, done: (Result<String>) -> Unit) {
        val token = storedToken(context)
        if (token.isNullOrBlank()) return done(Result.failure(IllegalStateException("Sign in first")))
        request(context, method, path, body, token, done)
    }

    private fun request(context: Context, method: String, path: String, body: JSONObject?, token: String?, done: (Result<String>) -> Unit) {
        if (!configured()) return done(Result.failure(IllegalStateException("Accounts are not available in this build")))
        Thread {
            val result = runCatching {
                val url = URL(API_BASE_URL.trimEnd('/') + path)
                require(url.protocol == "https") { "Account API requires HTTPS" }
                val connection = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = method; connectTimeout = 12_000; readTimeout = 15_000
                    setRequestProperty("Accept", "application/json")
                    token?.let { setRequestProperty("Authorization", "Bearer $it") }
                    if (body != null) { doOutput = true; setRequestProperty("Content-Type", "application/json; charset=utf-8") }
                }
                body?.let { connection.outputStream.use { out -> out.write(it.toString().toByteArray(Charsets.UTF_8)) } }
                val status = connection.responseCode
                val stream = if (status in 200..299) connection.inputStream else connection.errorStream
                val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
                connection.disconnect()
                if (status !in 200..299) throw IllegalStateException(JSONObject(text.ifBlank { "{}" }).optString("error", "Request failed ($status)"))
                text
            }
            main.post { done(result) }
        }.start()
    }
}
