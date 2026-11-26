/*
 * Copyright 2026 Davils
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

@file:Suppress("RedundantSuspendModifier")

package com.davils.krypt.ocsp

import com.davils.kontinuity.cache.Cache
import com.davils.kontinuity.cache.Eviction
import com.davils.kontinuity.cache.cache
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val CACHE_NAME: String = "krypt.ocsp.responses"

/**
 * A bounded cache of signed responses about one certificate each, as RFC 9919 responders keep them.
 *
 * The caller drives it: krypt starts no timer. An entry expires at the next update of its response and is dropped
 * when it is read after that. The entries live in a cache of kontinuity: every operation takes constant time however
 * full the cache is, and since 1.1.0 the entry used least recently makes room when it is full, instead of the entry
 * that expires first. The cache is safe to share between coroutines.
 *
 * @property capacity the most responses the cache holds.
 * @constructor Creates an empty cache.
 * @throws IllegalArgumentException if [capacity] is not between 1 and [HARD_MAXIMUM_CAPACITY].
 * @since 1.0.0
 */
public class OcspResponseCache(public val capacity: Int = DEFAULT_CAPACITY) {
    private val entries: Cache<CertId, CachedResponse> = cache(name = CACHE_NAME) {
        maximumSize = capacity.coerceIn(minimumValue = 1, maximumValue = HARD_MAXIMUM_CAPACITY)
        eviction = Eviction.Lru
    }

    init {
        require(capacity in 1..HARD_MAXIMUM_CAPACITY) { "A cache holds 1 to $HARD_MAXIMUM_CAPACITY responses" }
    }

    /**
     * Keeps [response] about [certId] until [nextUpdate], replacing an older one.
     *
     * @param certId the certificate.
     * @param response the DER encoding of the signed response.
     * @param nextUpdate when the response expires.
     * @since 1.0.0
     */
    public suspend fun put(certId: CertId, response: ByteString, nextUpdate: Instant) {
        entries.put(certId, CachedResponse(response = response, nextUpdate = nextUpdate))
    }

    /**
     * Returns the response about [certId] if it has not expired at [at].
     *
     * @param certId the certificate.
     * @param at the current time.
     * @return the DER encoding of the response, or null.
     * @since 1.0.0
     */
    public suspend fun get(certId: CertId, at: Instant): ByteString? {
        val cached = entries[certId] ?: return null
        val isFresh = cached.nextUpdate > at
        if (!isFresh) entries.remove(certId)
        return cached.response.takeIf { isFresh }
    }

    /**
     * Returns how many responses the cache holds, expired or not.
     *
     * @return the number of responses.
     * @since 1.0.0
     */
    public suspend fun size(): Int = entries.snapshot().size

    /**
     * Drops every response, such as after the issuer revoked many certificates at once.
     *
     * @since 1.0.0
     */
    public suspend fun clear() {
        entries.clear()
    }

    /**
     * Shows the size and the capacity.
     *
     * @return the cache as text.
     * @since 1.0.0
     */
    override fun toString(): String = "OcspResponseCache(capacity=$capacity)"

    /**
     * The capacities.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default capacity.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_CAPACITY: Int = 1_024

        /**
         * The hard ceiling of the capacity.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_CAPACITY: Int = 65_536
    }

    private data class CachedResponse(val response: ByteString, val nextUpdate: Instant)
}
