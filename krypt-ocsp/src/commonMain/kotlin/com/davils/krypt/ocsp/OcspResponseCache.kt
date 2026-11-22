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

package com.davils.krypt.ocsp

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * A bounded cache of signed responses about one certificate each, as RFC 9919 responders keep them.
 *
 * The caller drives it: krypt starts no timer. An entry expires at the next update of its response and is dropped
 * when it is read after that. When the cache is full, the entry that expires first makes room. The cache is safe to
 * share between coroutines.
 *
 * @property capacity the most responses the cache holds.
 * @constructor Creates an empty cache.
 * @throws IllegalArgumentException if [capacity] is not between 1 and [HARD_MAXIMUM_CAPACITY].
 * @since 1.0.0
 */
public class OcspResponseCache(public val capacity: Int = DEFAULT_CAPACITY) {
    private val lock = Mutex()
    private val certIds = mutableListOf<CertId>()
    private val responses = mutableListOf<ByteString>()
    private val expiries = mutableListOf<Instant>()

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
        lock.withLock {
            removeAt(certIds.indexOf(certId))
            val isFull = certIds.size >= capacity
            if (isFull) removeAt(expiries.indexOf(expiries.min()))
            certIds += certId
            responses += response
            expiries += nextUpdate
        }
    }

    /**
     * Returns the response about [certId] if it has not expired at [at].
     *
     * @param certId the certificate.
     * @param at the current time.
     * @return the DER encoding of the response, or null.
     * @since 1.0.0
     */
    public suspend fun get(certId: CertId, at: Instant): ByteString? = lock.withLock {
        val index = certIds.indexOf(certId)
        val isExpired = index >= 0 && expiries[index] <= at
        if (isExpired) removeAt(index)
        responses.getOrNull(certIds.indexOf(certId))
    }

    /**
     * Returns how many responses the cache holds, expired or not.
     *
     * @return the number of responses.
     * @since 1.0.0
     */
    public suspend fun size(): Int = lock.withLock { certIds.size }

    /**
     * Drops every response, such as after the issuer revoked many certificates at once.
     *
     * @since 1.0.0
     */
    public suspend fun clear() {
        lock.withLock {
            certIds.clear()
            responses.clear()
            expiries.clear()
        }
    }

    /**
     * Shows the size and the capacity.
     *
     * @return the cache as text.
     * @since 1.0.0
     */
    override fun toString(): String = "OcspResponseCache(capacity=$capacity)"

    private fun removeAt(index: Int) {
        if (index < 0) return
        certIds.removeAt(index)
        responses.removeAt(index)
        expiries.removeAt(index)
    }

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
}
