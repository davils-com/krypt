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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.spiffe.bundle

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.collection.OrderedSet
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.path.TrustAnchor
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private const val NONE: String = "none"

/**
 * The SPIFFE bundle of one trust domain, by the SPIFFE Trust Domain and Bundle specification: the X.509 authorities
 * that anchor its X.509-SVIDs and the JWT authorities that sign its JWT-SVIDs.
 *
 * A bundle belongs to exactly one trust domain; bundles of different trust domains are never merged, so that one
 * trust domain can never vouch for the ids of another. An empty bundle means that the trust domain revoked every key,
 * and every SVID of it is untrusted.
 *
 * Immutable and safe to share between threads.
 *
 * @property trustDomain the trust domain the bundle is authoritative for.
 * @param x509Authorities the X.509 authorities, each a certificate whose key krypt can use.
 * @param jwtAuthorities the JWT authorities, each with a key id of its own.
 * @property sequence the `spiffe_sequence` of the bundle, or null.
 * @property refreshHint the `spiffe_refresh_hint` of the bundle, or null.
 * @constructor Checks the bundle.
 * @throws IllegalArgumentException if [sequence] is negative or above the largest JSON integer of JOSE,
 *   [refreshHint] is negative, not whole seconds or above [MAXIMUM_REFRESH_HINT_SECONDS], two JWT authorities share
 *   a key id, an X.509 authority has no usable key, or there are more than [SpiffeLimits.HARD_MAXIMUM_AUTHORITIES]
 *   authorities.
 * @since 1.0.0
 */
public class TrustBundle(
    public val trustDomain: TrustDomain,
    x509Authorities: List<Certificate> = emptyList(),
    jwtAuthorities: List<JwtAuthority> = emptyList(),
    public val sequence: Long? = null,
    public val refreshHint: Duration? = null,
) {
    /**
     * The X.509 authorities, the roots of the X.509-SVIDs of the trust domain.
     *
     * @since 1.0.0
     */
    public val x509Authorities: List<Certificate> = x509Authorities.toList()

    /**
     * The JWT authorities, the keys of the JWT-SVIDs of the trust domain.
     *
     * @since 1.0.0
     */
    public val jwtAuthorities: List<JwtAuthority> = jwtAuthorities.toList()

    /**
     * Whether the bundle holds no authority, so that every SVID of the trust domain is untrusted.
     *
     * @since 1.0.0
     */
    public val isEmpty: Boolean get() = x509Authorities.isEmpty() && jwtAuthorities.isEmpty()

    private val values: List<Any?> get() = listOf(trustDomain, x509Authorities, jwtAuthorities, sequence, refreshHint)

    init {
        val isSequenced = sequence == null || sequence in 0..JsonValue.Integer.MAXIMUM
        val isHinted = refreshHint == null || isHint(refreshHint)
        val count = this.x509Authorities.size + this.jwtAuthorities.size
        val keyIds = OrderedSet(this.jwtAuthorities.map { authority -> authority.keyId })
        require(isSequenced) { "A sequence is 0 to ${JsonValue.Integer.MAXIMUM}" }
        require(isHinted) { "A refresh hint is whole seconds, 0 to $MAXIMUM_REFRESH_HINT_SECONDS" }
        require(count <= SpiffeLimits.HARD_MAXIMUM_AUTHORITIES) {
            "A bundle holds at most ${SpiffeLimits.HARD_MAXIMUM_AUTHORITIES} authorities"
        }
        require(keyIds.size == this.jwtAuthorities.size) { "The JWT authorities have distinct key ids" }
        require(this.x509Authorities.all { authority -> authority.publicKey != null }) {
            "The key of every X.509 authority is usable"
        }
    }

    /**
     * Returns the JWT authority with [keyId].
     *
     * @param keyId the key id, possibly from an attacker.
     * @return the authority, or null if the bundle has none with this key id.
     * @since 1.0.0
     */
    public fun jwtAuthority(keyId: String): JwtAuthority? = jwtAuthorities.firstOrNull { found -> found.keyId == keyId }

    /**
     * Returns the X.509 authorities as trust anchors of path validation, with their name constraints.
     *
     * @return the anchors.
     * @since 1.0.0
     */
    public fun trustAnchors(): List<TrustAnchor> = x509Authorities.map { authority -> TrustAnchor.of(authority) }

    /**
     * Compares the trust domain, the authorities, the sequence and the refresh hint.
     *
     * @param other the other object.
     * @return true if [other] is the same bundle.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is TrustBundle && values == other.values

    /**
     * Hashes the trust domain, the authorities, the sequence and the refresh hint.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the trust domain, the number of authorities, the sequence and the refresh hint.
     *
     * @return the bundle as text.
     * @since 1.0.0
     */
    override fun toString(): String = "TrustBundle($trustDomain, x509=${x509Authorities.size}, " +
        "jwt=${jwtAuthorities.size}, sequence=${sequence ?: NONE}, refreshHint=${refreshHint ?: NONE})"

    /**
     * The bounds of a bundle.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The longest refresh hint in seconds, 2^32 - 1, more than a century.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_REFRESH_HINT_SECONDS: Long = 4_294_967_295L

        private val MAXIMUM_HINT: Duration = MAXIMUM_REFRESH_HINT_SECONDS.seconds

        private fun isHint(hint: Duration): Boolean {
            val whole = hint.inWholeSeconds.seconds
            return !hint.isNegative() && hint == whole && hint <= MAXIMUM_HINT
        }
    }
}
