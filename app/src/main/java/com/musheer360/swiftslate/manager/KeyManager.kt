package com.musheer360.swiftslate.manager

import android.content.Context
import android.content.SharedPreferences
import com.musheer360.swiftslate.model.PrefKeys
import com.musheer360.swiftslate.model.ProviderType
import org.json.JSONArray
import java.util.concurrent.atomic.AtomicInteger

class KeyManager internal constructor(
    context: Context,
    private val cipher: KeyCipher
) {
    constructor(context: Context) : this(context, AndroidKeystoreCipher())

    private val prefs: SharedPreferences = context.getSharedPreferences("secure_keys_prefs", Context.MODE_PRIVATE)
    private val settingsPrefs: SharedPreferences = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    /**
     * Keys live in one pool per provider (smart upgrades), so a command can fall back to a
     * second provider with that provider's own keys. Before pools, a single shared array
     * served whichever provider was active; [getKeys] migrates it into the active
     * provider's pool on first read.
     */
    private fun storageKeyFor(pool: String): String = "keys_array_$pool"

    /** The pool UI-facing calls operate on: the currently active provider's. */
    fun activePool(): String = ProviderType.sanitize(
        try { settingsPrefs.getString(PrefKeys.PROVIDER_TYPE, null) } catch (_: Exception) { null }
    )

    companion object {
        private const val PREF_KEY_ARRAY = "keys_array"
        private const val CACHE_TTL_MS = 5_000L
        private const val MAX_KEY_LENGTH = 256
        // Invalid-key marks expire. A 403 is not always the key's fault (e.g. selecting a
        // model the key's project can't access returns 403 for every key), and marks used
        // to last for the whole process lifetime — so one bad model choice permanently
        // killed every key with no recovery except re-adding them all.
        private const val INVALID_KEY_TTL_MS = 900_000L // 15 min

        /**
         * Whether [stored] is a pre-encryption plaintext JSON array rather than ciphertext.
         *
         * This used to be `!stored.contains("]")`, which is wrong: the legacy format is a JSON
         * array, and `["key"]` contains that separator. Legacy values were therefore routed
         * straight to decrypt(), which split them on "]", failed, and made getKeys() return —
         * and cache — an empty list. Anyone upgrading from a plaintext build silently lost every
         * key. Ciphertext is "<base64>]<base64>" and base64 never starts with "[", so the two
         * shapes are unambiguous.
         */
        internal fun isLegacyPlaintext(stored: String): Boolean = stored.trimStart().startsWith("[")
    }

    private val rateLimitedKeys = java.util.concurrent.ConcurrentHashMap<String, Long>()
    /** key -> timestamp after which the invalid mark is forgotten. */
    private val invalidKeys = java.util.concurrent.ConcurrentHashMap<String, Long>()
    private val roundRobinIndex = AtomicInteger(0)
    @Volatile
    private var cachedKeys: List<String>? = null
    @Volatile
    private var cacheTimestamp = 0L
    /**
     * Ciphertext [cachedKeys] was decrypted from, so an expired TTL can be revalidated with a
     * string compare instead of another AndroidKeyStore round trip + AES-GCM decrypt. The TTL
     * used to be what let the UI's instance notice the accessibility service's writes; every
     * caller now shares [com.musheer360.swiftslate.SwiftSlateApp.keyManager], so it is only a
     * backstop against prefs changing underneath a single instance.
     */
    @Volatile
    private var cachedCipherText: String? = null
    /** Pool [cachedKeys] belongs to. Pools share one cache slot; switching pools reloads. */
    @Volatile
    private var cachedPool: String? = null

    val keystoreAvailable: Boolean get() = cipher.available

    private fun JSONArray.toStringList(): List<String> =
        (0 until length()).map { getString(it) }

    @Synchronized
    fun getKeys(pool: String = activePool()): List<String> {
        val now = System.currentTimeMillis()
        val cached = cachedKeys
        if (cached != null && cachedPool == pool && now - cacheTimestamp < CACHE_TTL_MS) return cached
        val poolKey = storageKeyFor(pool)
        var stored = prefs.getString(poolKey, null)
        if (stored == null && pool == activePool()) {
            // One-time pool migration: the pre-pool store held one shared array, which belongs
            // to whichever provider was active when pools landed. Move it raw — the value is
            // decoded below by the same legacy/ciphertext paths either way.
            val legacy = prefs.getString(PREF_KEY_ARRAY, null)
            if (legacy != null) {
                prefs.edit().putString(poolKey, legacy).remove(PREF_KEY_ARRAY).apply()
                stored = legacy
            }
        }
        val storedValue = stored ?: return emptyList()
        // TTL expired but the stored ciphertext is byte-identical, so the plaintext cannot have
        // changed: revalidate the cache rather than paying for another KeyStore decrypt. Without
        // this, every 5s of active typing re-ran AES-GCM on the accessibility service's path.
        if (cached != null && cachedPool == pool && storedValue == cachedCipherText) {
            cacheTimestamp = now
            return cached
        }
        // Legacy plaintext migration — can be removed once all users are on an encrypted build.
        if (isLegacyPlaintext(storedValue)) {
            return try {
                val encrypted = cipher.encrypt(storedValue)
                prefs.edit().putString(poolKey, encrypted).commit()
                val list = JSONArray(storedValue).toStringList()
                cacheKeys(list, encrypted, pool)
                list
            } catch (_: Exception) {
                // Encryption failed (e.g. keystore invalidated) — return the plaintext keys so
                // the user does not lose access, without caching or rewriting anything.
                try { JSONArray(storedValue).toStringList() } catch (_: Exception) { emptyList() }
            }
        }
        val jsonStr = cipher.decrypt(storedValue) ?: run {
            cacheKeys(emptyList(), storedValue, pool)
            return emptyList()
        }
        val list = try { JSONArray(jsonStr).toStringList() } catch (_: Exception) { emptyList() }
        cacheKeys(list, storedValue, pool)
        return list
    }

    private fun cacheKeys(keys: List<String>, cipherText: String?, pool: String) {
        cachedKeys = keys
        cachedCipherText = cipherText
        cachedPool = pool
        cacheTimestamp = System.currentTimeMillis()
    }

    @Synchronized
    private fun saveKeys(keys: List<String>, pool: String): Boolean {
        val arr = JSONArray(keys)
        return try {
            val cipherText = cipher.encrypt(arr.toString())
            prefs.edit().putString(storageKeyFor(pool), cipherText).apply()
            cacheKeys(keys, cipherText, pool)
            true
        } catch (_: Exception) {
            // Invalidate: the stored value and the in-memory list may now disagree.
            cachedKeys = null
            cachedCipherText = null
            cachedPool = null
            cacheTimestamp = 0L
            false
        }
    }

    @Synchronized
    fun addKey(key: String): Boolean {
        if (key.isBlank() || key.length > MAX_KEY_LENGTH) return false
        val pool = activePool()
        val keys = getKeys(pool).toMutableList()
        if (!keys.contains(key)) {
            keys.add(key)
            if (!saveKeys(keys, pool)) return false
        }
        invalidKeys.remove(key)
        return true
    }

    @Synchronized
    fun removeKey(key: String): Boolean {
        val pool = activePool()
        val keys = getKeys(pool).toMutableList()
        keys.remove(key)
        val saved = saveKeys(keys, pool)
        rateLimitedKeys.remove(key)
        invalidKeys.remove(key)
        return saved
    }

    // All @Synchronized methods use `this` as monitor (reentrant).
    // getNextKey() intentionally calls getKeys() while holding the lock.
    /**
     * Next usable key, skipping benched ones and anything in [alreadyTried].
     *
     * [alreadyTried] exists because a monotonic round-robin index modulo a *shrinking* list is
     * not a permutation: with keys [A,B,C] and the counter at 1, a 5xx on B followed by a 429 on
     * C mapped attempt 3 back to B — re-sending a byte-identical request while A was never tried
     * at all, so the command could fail with a healthy key sitting idle.
     */
    @Synchronized
    fun getNextKey(alreadyTried: Set<String> = emptySet(), pool: String = activePool()): String? {
        val keys = getKeys(pool)
        if (keys.isEmpty()) return null

        val now = System.currentTimeMillis()
        val validKeys = keys.filter { key ->
            if (key in alreadyTried) return@filter false
            if (isInvalid(key)) return@filter false
            val limitTime = rateLimitedKeys[key] ?: 0L
            now > limitTime
        }

        if (validKeys.isEmpty()) return null

        val idx = (roundRobinIndex.getAndIncrement() and Int.MAX_VALUE) % validKeys.size
        return validKeys[idx]
    }

    fun reportRateLimit(key: String, retryAfterSeconds: Long = 60) {
        val cooldown = retryAfterSeconds.coerceIn(1, 600)
        rateLimitedKeys[key] = System.currentTimeMillis() + cooldown * 1_000
    }

    fun markInvalid(key: String) {
        invalidKeys[key] = System.currentTimeMillis() + INVALID_KEY_TTL_MS
    }

    /**
     * Clears any in-memory invalid/rate-limit marks for [key] so it is usable again on the
     * next attempt. Called when the user re-adds a key: previously the UI's "already added"
     * early-return skipped [addKey]'s un-benching, leaving the accessibility service benching
     * the key for the full 15-minute TTL even after the user fixed it.
     */
    @Synchronized
    fun clearMarks(key: String) {
        invalidKeys.remove(key)
        rateLimitedKeys.remove(key)
    }

    /**
     * Whether [key] is currently benched as invalid, expiring the mark if it is due.
     * Self-healing: without expiry a transient 403 killed the key until the process
     * restarted (see [INVALID_KEY_TTL_MS]).
     */
    private fun isInvalid(key: String): Boolean {
        val until = invalidKeys[key] ?: return false
        if (System.currentTimeMillis() >= until) {
            invalidKeys.remove(key)
            return false
        }
        return true
    }

    fun getShortestWaitTimeMs(pool: String = activePool()): Long? {
        val keys = getKeys(pool)
        if (keys.isEmpty()) return null
        val now = System.currentTimeMillis()
        val waits = keys.filter { !isInvalid(it) }
            .mapNotNull { key ->
                val limitTime = rateLimitedKeys[key] ?: return@mapNotNull null
                val remaining = limitTime - now
                if (remaining > 0) remaining else null
            }
        return waits.minOrNull()
    }
}
