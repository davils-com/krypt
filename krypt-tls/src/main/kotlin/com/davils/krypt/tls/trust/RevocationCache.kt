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

@file:OptIn(ExperimentalAtomicApi::class)

package com.davils.krypt.tls.trust

import com.davils.krypt.tls.internal.CachedStatus
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.path.RevocationStatus
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

/**
 * A bounded cache of the revocation status of certificates that the trust manager fills and the application drives.
 *
 * Only a good or a revoked status is kept, each for [lifetime]; an unknown status is never cached. The cache starts no
 * timer: an entry is ignored once it expired and removed by the next [put] or by [prune], which the application calls
 * when it likes. When the cache is full, the oldest entry gives way. A stapled OCSP response is checked before the
 * cache, so a peer that staples is never judged by an older status.
 *
 * Safe to share between threads.
 *
 * @property capacity the most entries the cache holds.
 * @property lifetime how long an entry counts.
 * @constructor Creates an empty cache.
 * @throws IllegalArgumentException if [capacity] lies outside 1 to [HARD_MAXIMUM_CAPACITY] or [lifetime] outside a
 *   positive time up to [HARD_MAXIMUM_LIFETIME].
 * @since 1.0.0
 */
public class RevocationCache(
    public val capacity: Int = DEFAULT_CAPACITY,
    public val lifetime: Duration = DEFAULT_LIFETIME,
) {
    private val lock = Any()

    private val entries = AtomicReference<List<CachedStatus>>(emptyList())

    init {
        require(capacity in 1..HARD_MAXIMUM_CAPACITY) { "A revocation cache holds 1 to $HARD_MAXIMUM_CAPACITY entries" }
        require(lifetime.isPositive() && lifetime <= HARD_MAXIMUM_LIFETIME) {
            "An entry counts for a positive time of at most $HARD_MAXIMUM_LIFETIME"
        }
    }

    /**
     * The number of entries, expired ones included until they are removed.
     *
     * @since 1.0.0
     */
    public val size: Int get() = entries.load().size

    /**
     * Returns the status of [certificate] if an entry for it counts at [at].
     *
     * @param certificate the certificate.
     * @param at the time.
     * @return the good or revoked status, or null.
     * @since 1.0.0
     */
    public fun status(certificate: Certificate, at: Instant): RevocationStatus? {
        val entry = entries.load().firstOrNull { found -> found.certificate == certificate && at < found.expiresAt }
        return entry?.status
    }

    /**
     * Records the status of [certificate] from [at] on, replacing an older entry and removing the expired ones.
     *
     * @param certificate the certificate.
     * @param status its status; an unknown status is ignored.
     * @param at the time the status was learned.
     * @since 1.0.0
     */
    public fun put(certificate: Certificate, status: RevocationStatus, at: Instant) {
        if (status == RevocationStatus.Unknown) return
        val entry = CachedStatus(certificate = certificate, status = status, expiresAt = at + lifetime)
        synchronized(lock) {
            val kept = entries.load().filter { found -> found.certificate != certificate && at < found.expiresAt }
            entries.store(kept.takeLast(capacity - 1) + entry)
        }
    }

    /**
     * Removes every entry that expired at [at].
     *
     * @param at the time.
     * @return how many entries were removed.
     * @since 1.0.0
     */
    public fun prune(at: Instant): Int {
        synchronized(lock) {
            val current = entries.load()
            val kept = current.filter { found -> at < found.expiresAt }
            entries.store(kept)
            return current.size - kept.size
        }
    }

    /**
     * Removes every entry, such as after the trust of the application changed.
     *
     * @since 1.0.0
     */
    public fun clear() {
        entries.store(emptyList())
    }

    /**
     * Shows the bounds and the size.
     *
     * @return the cache as text.
     * @since 1.0.0
     */
    override fun toString(): String = "RevocationCache(capacity=$capacity, lifetime=$lifetime, size=$size)"

    /**
     * The defaults and bounds of a cache.
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
         * The most entries any cache holds.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_CAPACITY: Int = 65_536

        /**
         * The default lifetime of an entry: one hour.
         *
         * @since 1.0.0
         */
        public val DEFAULT_LIFETIME: Duration = 1.hours

        /**
         * The longest lifetime of an entry: seven days, the longest validity of an OCSP response krypt accepts.
         *
         * @since 1.0.0
         */
        public val HARD_MAXIMUM_LIFETIME: Duration = 7.days
    }
}
