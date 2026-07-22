package com.privacyshield.proxy.core

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.io.BufferedReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Tiny Supabase client (auth + a single per-user JSON backup blob), built on HttpURLConnection so
 * it needs no extra dependencies. Shared project with the Privacy Shield desktop app.
 *
 * Auth is passwordless: a 6-digit email code (OTP). A signed-in session (access/refresh token +
 * user id) is cached in prefs so the app stays logged in. Data: one row per user in
 * `public.app_backups` (app='shieldproxy'), holding a JSON blob of proxies.json + profiles.json so
 * a new phone restores the exact setup.
 */
object Supabase {
    // ShieldProxy / BlackBox project (NOT the PrivacyShield desktop project).
    const val URL = "https://oqyrbdvehvqdcpglaojo.supabase.co"
    // Publishable/anon key — safe to embed; Row Level Security enforces per-user isolation.
    const val ANON = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9xeXJiZHZlaHZxZGNwZ2xhb2pvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQzODEzMDgsImV4cCI6MjA5OTk1NzMwOH0.BdkGNtzNkN1BV50FA2aA817SAAHvD_2hfAI1lU_bxOw"

    private const val PREFS = "sb_session"
    private const val BACKUP_KEY_FIELD = "shieldbox_backup_key_v1"
    private const val RECOVERY_KEY_APP = "_shieldbox_recovery_key_v1"
    private const val PENDING_LOGOUT_PREFS = "sb_pending_logout"
    private const val CLOCK_SKEW_SECONDS = 30L
    private const val VALIDATION_MAX_AGE_MS = 120_000L
    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val validatedThisProcess = AtomicBoolean(false)
    private val validatedAtMs = AtomicLong(0L)

    private fun secret(ctx: Context, name: String) =
        SessionCrypto.open(ctx, prefs(ctx).getString("${name}_sealed", null))
            ?: prefs(ctx).getString(name, null) // one-time compatibility with the earlier build
    // Persistent session: signed in as long as tokens are stored on this device. No expiry, no
    // freshness window, no auto-logout — only an explicit signOut() clears it. The refresh token
    // silently keeps API calls alive in the background.
    /** Unlock only after this process has verified the stored session with GoTrue recently. */
    fun isSignedIn(ctx: Context): Boolean {
        if (!hasStoredSession(ctx) || !validatedThisProcess.get() || !tokenIsFresh(accessToken(ctx))) {
            return false
        }
        val age = System.currentTimeMillis() - validatedAtMs.get()
        return age in 0..VALIDATION_MAX_AGE_MS
    }
    fun hasStoredSession(ctx: Context): Boolean =
        !accessToken(ctx).isNullOrBlank() && !refreshToken(ctx).isNullOrBlank()
    fun email(ctx: Context): String? = secret(ctx, "email")
    fun userId(ctx: Context): String? = secret(ctx, "user_id")
    private fun accessToken(ctx: Context): String? = secret(ctx, "access_token")
    private fun refreshToken(ctx: Context): String? = secret(ctx, "refresh_token")

    fun signOut(ctx: Context) {
        val access = accessToken(ctx)
        val refresh = refreshToken(ctx)
        if (!access.isNullOrBlank()) {
            ctx.getSharedPreferences(PENDING_LOGOUT_PREFS, Context.MODE_PRIVATE).edit()
                .putString("access_sealed", SessionCrypto.seal(ctx, access))
                .putString("refresh_sealed", SessionCrypto.seal(ctx, refresh.orEmpty()))
                .apply()
        }
        clearLocalSession(ctx)
        retryPendingLogoutAsync(ctx.applicationContext)
    }

    private fun saveSession(ctx: Context, o: JSONObject) {
        val user = o.optJSONObject("user")
        val access = o.optString("access_token")
        val refresh = o.optString("refresh_token")
        require(access.isNotBlank() && refresh.isNotBlank() && user != null) { "Invalid login session" }
        prefs(ctx).edit().clear()
            .putString("access_token_sealed", SessionCrypto.seal(ctx, access))
            .putString("refresh_token_sealed", SessionCrypto.seal(ctx, refresh))
            .putString("user_id_sealed", SessionCrypto.seal(ctx, user?.optString("id").orEmpty()))
            .putString("email_sealed", SessionCrypto.seal(ctx, user?.optString("email").orEmpty()))
            .commit()
        validatedThisProcess.set(true)
        validatedAtMs.set(System.currentTimeMillis())
    }

    private fun clearLocalSession(ctx: Context) {
        validatedThisProcess.set(false)
        validatedAtMs.set(0L)
        prefs(ctx).edit().clear().commit()
    }

    class AuthException(msg: String) : Exception(msg)

    // ---- Passwordless email-code (OTP) auth ---------------------------------

    /** Send a 6-digit login code to [email]. Creates the account on first use. Same call is used
     *  for both sign-up and sign-in — the code is how the user proves the email is theirs. */
    fun requestEmailCode(ctx: Context, email: String) {
        val body = JSONObject().put("email", email).put("create_user", true)
        try {
            post("$URL/auth/v1/otp", body.toString(), null)   // 200 {} on success
        } catch (e: HttpError) {
            throw AuthException(
                when (e.code) {
                    429 -> "Please wait a minute before requesting another code."
                    else -> e.message ?: "Could not send the code. Check your connection."
                }
            )
        }
    }

    /** Verify the emailed 6-digit [code] and store the session. */
    fun verifyEmailCode(ctx: Context, email: String, code: String) {
        val body = JSONObject().put("email", email).put("token", code.trim()).put("type", "email")
        val resp = try {
            post("$URL/auth/v1/verify", body.toString(), null)
        } catch (e: HttpError) {
            throw AuthException(
                if (e.code == 403 || e.code == 401) "That code is wrong or expired. Request a new one."
                else e.message ?: "Could not verify the code."
            )
        }
        val o = JSONObject(resp)
        if (!o.has("access_token")) throw AuthException("Could not verify the code. Try again.")
        saveSession(ctx, o)
    }

    /** Cold-start gate: GoTrue must accept (or refresh) the stored session before unlock. */
    @Synchronized
    fun validateStoredSession(ctx: Context): Boolean {
        if (!hasStoredSession(ctx)) return false
        return try {
            val user = getCurrentUser(ctx)
            val valid = user.optString("id") == userId(ctx) &&
                user.optString("email").equals(email(ctx), ignoreCase = true) &&
                tokenIsFresh(accessToken(ctx))
            if (valid) {
                validatedThisProcess.set(true)
                validatedAtMs.set(System.currentTimeMillis())
            } else clearLocalSession(ctx)
            valid
        } catch (e: HttpError) {
            // Definitive auth rejection: discard unusable credentials. Server/network failures
            // leave the sealed session in place so the gate can offer a safe retry.
            if (e.code == 401 || e.code == 403) clearLocalSession(ctx)
            false
        } catch (_: Exception) {
            false
        }
    }

    /**
     * A random account recovery key is kept in private Supabase user metadata. Google Drive has
     * the encrypted backup but not this key, while Supabase has the key but not the Drive files.
     * Password changes therefore do not destroy access to existing backups.
     */
    fun getOrCreateBackupKey(ctx: Context): ByteArray = getBackupKeyCandidates(ctx).first()

    /** Canonical recovery key followed by any older metadata key still needed to unlock data
     * created before cross-app atomic provisioning was introduced. */
    @Synchronized
    fun getBackupKeyCandidates(ctx: Context): List<ByteArray> {
        fun decodeLegacy(user: JSONObject): ByteArray? = runCatching {
            Base64.decode(user.optJSONObject("user_metadata")
                ?.optString(BACKUP_KEY_FIELD), Base64.NO_WRAP)
                .takeIf { it.size == 32 }
        }.getOrNull()

        val legacy = decodeLegacy(getCurrentUser(ctx))
        val primary = runCatching {
            val candidate = legacy ?: ByteArray(32).also(SecureRandom()::nextBytes)
            val row = JSONObject().put("app", RECOVERY_KEY_APP).put("data",
                JSONObject().put("key", Base64.encodeToString(candidate, Base64.NO_WRAP)))
            restInsertIgnore(ctx, "$URL/rest/v1/app_backups?on_conflict=user_id,app", "[$row]")

            val response = restRead(ctx,
                "$URL/rest/v1/app_backups?app=eq.$RECOVERY_KEY_APP&select=data&limit=1")
                ?: error("Could not read the account recovery key")
            val rows = org.json.JSONArray(response)
            require(rows.length() == 1) { "Could not create the account recovery key" }
            Base64.decode(rows.getJSONObject(0).getJSONObject("data").getString("key"), Base64.NO_WRAP)
                .takeIf { it.size == 32 } ?: error("Invalid account recovery key")
        }.getOrElse { failure ->
            // Accounts created before atomic provisioning already have their immutable key in
            // private auth metadata. A temporary REST/schema outage must not lock those users out
            // of files that can still be authenticated with that exact key. New accounts remain
            // fail-closed because they have no previously provisioned key to fall back to.
            legacy?.let {
                android.util.Log.w("ShieldKeyRecovery",
                    "Atomic recovery-key store unavailable; using verified legacy candidate (${failure.javaClass.simpleName})")
                return listOf(it)
            }
            throw IllegalStateException("Could not verify the account recovery key", failure)
        }
        android.util.Log.i("ShieldKeyRecovery",
            "Server recovery keys: legacyPresent=${legacy != null}; legacyMatchesPrimary=${legacy?.contentEquals(primary) == true}")
        return buildList {
            // Existing accounts encrypted their first backups with the metadata key. Preserve it
            // as primary when present; the atomic row remains the fallback for newer accounts.
            legacy?.let(::add)
            if (none { it.contentEquals(primary) }) add(primary)
        }
    }

    private fun getCurrentUser(ctx: Context): JSONObject =
        JSONObject(authorizedGet(ctx, "$URL/auth/v1/user"))

    /** Refresh the access token when it 401s. Returns true if refreshed. */
    private fun refresh(ctx: Context): Boolean {
        val rt = refreshToken(ctx) ?: return false
        // Never clear the session on a failed refresh — a network blip must not log the user out.
        // Only an explicit signOut() ends the session.
        return try {
            val o = JSONObject(post("$URL/auth/v1/token?grant_type=refresh_token",
                JSONObject().put("refresh_token", rt).toString(), null))
            if (o.has("access_token")) { saveSession(ctx, o); true } else false
        } catch (_: Exception) {
            false
        }
    }

    private fun tokenIsFresh(token: String?): Boolean {
        if (token.isNullOrBlank()) return false
        return runCatching {
            val payload = token.split('.').getOrNull(1) ?: return@runCatching false
            val decoded = String(Base64.decode(payload,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))
            SessionPolicy.tokenExpiryIsUsable(JSONObject(decoded).optLong("exp", 0L),
                System.currentTimeMillis(), CLOCK_SKEW_SECONDS)
        }.getOrDefault(false)
    }

    fun retryPendingLogoutAsync(ctx: Context) {
        Thread { retryPendingLogout(ctx.applicationContext) }.start()
    }

    private fun retryPendingLogout(ctx: Context) {
        val pending = ctx.getSharedPreferences(PENDING_LOGOUT_PREFS, Context.MODE_PRIVATE)
        val access = SessionCrypto.open(ctx, pending.getString("access_sealed", null)) ?: return
        val refresh = SessionCrypto.open(ctx, pending.getString("refresh_sealed", null)).orEmpty()
        val revoked = runCatching {
            post("$URL/auth/v1/logout?scope=local", "{}", access)
            true
        }.recoverCatching {
            if (refresh.isBlank()) false else {
                val refreshed = JSONObject(post("$URL/auth/v1/token?grant_type=refresh_token",
                    JSONObject().put("refresh_token", refresh).toString(), null))
                val current = refreshed.optString("access_token")
                if (current.isBlank()) false
                else { post("$URL/auth/v1/logout?scope=local", "{}", current); true }
            }
        }.getOrDefault(false)
        if (revoked) pending.edit().clear().commit()
    }

    /** Push the app's whole config blob (upsert one row for this user). */
    fun pushBackup(ctx: Context, dataJson: String) {
        val row = JSONObject().put("app", "shieldproxy").put("data", JSONObject(dataJson))
        restWrite(ctx, "$URL/rest/v1/app_backups?on_conflict=user_id,app",
            "[" + row.toString() + "]")
    }

    /** Pull this user's config blob, or null if none stored yet. */
    fun pullBackup(ctx: Context): String? {
        val resp = restRead(ctx, "$URL/rest/v1/app_backups?app=eq.shieldproxy&select=data") ?: return null
        val arr = org.json.JSONArray(resp)
        if (arr.length() == 0) return null
        return arr.getJSONObject(0).optJSONObject("data")?.toString()
    }

    // ---- Remote control (emergency kill switch) ------------------------------
    private const val CONTROL_FIELD = "shieldproxy_control"

    /** Read the remote-control object from user_metadata, or null if none set. */
    fun readControl(ctx: Context): JSONObject? =
        getCurrentUser(ctx).optJSONObject("user_metadata")?.optJSONObject(CONTROL_FIELD)

    /** Write the remote-control object into user_metadata (visible to all this user's devices). */
    fun writeControl(ctx: Context, control: JSONObject) {
        val data = JSONObject().put(CONTROL_FIELD, control)
        authorizedPut(ctx, "$URL/auth/v1/user", JSONObject().put("data", data).toString())
    }

    /**
     * Best-effort upload of scrubbed crash reports to an optional `crash_reports` table
     * (columns: user_id uuid default auth.uid(), app text, report jsonb). Returns false — so the
     * reports stay queued locally — if the table doesn't exist or the network fails.
     */
    fun uploadCrashes(ctx: Context, reports: org.json.JSONArray): Boolean {
        if (reports.length() == 0) return true
        val rows = org.json.JSONArray()
        for (i in 0 until reports.length()) {
            rows.put(JSONObject().put("app", "shieldproxy").put("report", reports.getJSONObject(i)))
        }
        return try {
            restWrite(ctx, "$URL/rest/v1/crash_reports", rows.toString())
            true
        } catch (_: Exception) {
            false
        }
    }

    // ---- HTTP helpers --------------------------------------------------------

    private fun restWrite(ctx: Context, url: String, jsonArrayBody: String) {
        val token = accessToken(ctx) ?: throw AuthException("Not signed in")
        try {
            post(url, jsonArrayBody, token, prefer = "resolution=merge-duplicates,return=minimal")
        } catch (e: HttpError) {
            if (e.code == 401 && refresh(ctx)) {
                post(url, jsonArrayBody, accessToken(ctx), prefer = "resolution=merge-duplicates,return=minimal")
            } else throw e
        }
    }

    /** Atomic insert used for immutable per-account material; an existing row always wins. */
    private fun restInsertIgnore(ctx: Context, url: String, jsonArrayBody: String) {
        val token = accessToken(ctx) ?: throw AuthException("Not signed in")
        try {
            post(url, jsonArrayBody, token, prefer = "resolution=ignore-duplicates,return=minimal")
        } catch (e: HttpError) {
            if (e.code == 401 && refresh(ctx)) {
                post(url, jsonArrayBody, accessToken(ctx),
                    prefer = "resolution=ignore-duplicates,return=minimal")
            } else throw e
        }
    }

    private fun restRead(ctx: Context, url: String): String? {
        val token = accessToken(ctx) ?: return null
        return try {
            get(url, token)
        } catch (e: HttpError) {
            if (e.code == 401 && refresh(ctx)) get(url, accessToken(ctx)) else throw e
        }
    }

    private fun authorizedGet(ctx: Context, url: String): String {
        val token = accessToken(ctx) ?: throw AuthException("Not signed in")
        return try { get(url, token) }
        catch (e: HttpError) {
            if (e.code == 401 && refresh(ctx)) get(url, accessToken(ctx)) else throw e
        }
    }

    private fun authorizedPut(ctx: Context, url: String, body: String): String {
        val token = accessToken(ctx) ?: throw AuthException("Not signed in")
        return try { put(url, body, token) }
        catch (e: HttpError) {
            if (e.code == 401 && refresh(ctx)) put(url, body, accessToken(ctx)) else throw e
        }
    }

    private class HttpError(val code: Int, msg: String) : Exception(msg)

    private fun post(url: String, body: String, bearer: String?, prefer: String? = null): String {
        val c = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 15000; readTimeout = 20000
            setRequestProperty("apikey", ANON)
            setRequestProperty("Content-Type", "application/json")
            bearer?.let { setRequestProperty("Authorization", "Bearer $it") }
            prefer?.let { setRequestProperty("Prefer", it) }
        }
        OutputStreamWriter(c.outputStream).use { it.write(body) }
        return readResponse(c)
    }

    private fun get(url: String, bearer: String?): String {
        val c = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 15000; readTimeout = 20000
            setRequestProperty("apikey", ANON)
            bearer?.let { setRequestProperty("Authorization", "Bearer $it") }
        }
        return readResponse(c)
    }

    private fun put(url: String, body: String, bearer: String?): String {
        val c = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "PUT"; doOutput = true
            connectTimeout = 15000; readTimeout = 20000
            setRequestProperty("apikey", ANON)
            setRequestProperty("Content-Type", "application/json")
            bearer?.let { setRequestProperty("Authorization", "Bearer $it") }
        }
        OutputStreamWriter(c.outputStream).use { it.write(body) }
        return readResponse(c)
    }

    private fun readResponse(c: HttpURLConnection): String {
        val code = c.responseCode
        val stream = if (code in 200..299) c.inputStream else c.errorStream
        val text = stream?.bufferedReader()?.use(BufferedReader::readText) ?: ""
        if (code !in 200..299) {
            val readable = runCatching {
                val json = JSONObject(text)
                if (json.optString("error_code") == "user_already_exists")
                    "Account already exists. Tap Log in."
                else json.optString("msg", json.optString("error_description", "Request failed"))
            }.getOrDefault("Request failed")
            throw HttpError(code, readable)
        }
        return text
    }
}
