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

package com.davils.krypt.cose.cwt

import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.cbor.CborText
import com.davils.krypt.cose.internal.HeaderRules
import com.davils.krypt.cose.internal.NumericDates
import com.davils.krypt.cose.internal.bytesAt
import com.davils.krypt.cose.internal.labelOf
import com.davils.krypt.cose.internal.longOrNull
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * The claims set of a CBOR Web Token by RFC 8392, with typed access to its registered claims.
 *
 * The claims are checked on creation: every key is an integer or a text, `iss` and `sub` are texts, `aud` is a text
 * or a non-empty array of texts, `exp`, `nbf` and `iat` are NumericDates (integers, or finite floats for a fraction
 * of a second) and `cti` is a byte string. Claims are immutable and safe to share between threads.
 *
 * @property claims every claim.
 * @since 1.0.0
 */
public class CwtClaims private constructor(public val claims: CborMap) {
    /**
     * The `iss` claim, or null.
     *
     * @since 1.0.0
     */
    public val issuer: String? get() = claims[ISSUER]?.textOrNull()

    /**
     * The `sub` claim, or null.
     *
     * @since 1.0.0
     */
    public val subject: String? get() = claims[SUBJECT]?.textOrNull()

    /**
     * The audiences of the `aud` claim, empty if it is absent.
     *
     * @since 1.0.0
     */
    public val audience: List<String>
        get() {
            val item = claims[AUDIENCE]
            val single = item?.textOrNull()?.let { text -> listOf(text) }
            val several = item?.itemsOrNull().orEmpty()
            return single ?: several.mapNotNull { entry -> entry.textOrNull() }
        }

    /**
     * The `exp` claim, or null.
     *
     * @since 1.0.0
     */
    public val expiration: Instant? get() = claims[EXPIRATION]?.let { item -> NumericDates.of(item) }

    /**
     * The `nbf` claim, or null.
     *
     * @since 1.0.0
     */
    public val notBefore: Instant? get() = claims[NOT_BEFORE]?.let { item -> NumericDates.of(item) }

    /**
     * The `iat` claim, or null.
     *
     * @since 1.0.0
     */
    public val issuedAt: Instant? get() = claims[ISSUED_AT]?.let { item -> NumericDates.of(item) }

    /**
     * The `cti` claim, or null.
     *
     * @since 1.0.0
     */
    public val cwtId: ByteString? get() = claims.bytesAt(CWT_ID)

    /**
     * Returns the claim with the integer key [key].
     *
     * @param key the key.
     * @return the value, or null if the claim is absent.
     * @since 1.0.0
     */
    public operator fun get(key: Long): CborItem? = claims[key]

    /**
     * Returns the claim with [key], an integer or a text.
     *
     * @param key the key.
     * @return the value, or null if the claim is absent.
     * @since 1.0.0
     */
    public operator fun get(key: CborItem): CborItem? = claims[key]

    /**
     * Compares the claims.
     *
     * @param other the other object.
     * @return true if [other] has the same claims.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CwtClaims && claims == other.claims

    /**
     * Hashes the claims.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = claims.hashCode()

    /**
     * Shows the claims in the diagnostic notation of CBOR, escaping their text.
     *
     * @return the claims as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CwtClaims($claims)"

    /**
     * The keys of the registered claims and the factories of a claims set.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The key of `iss`.
         *
         * @since 1.0.0
         */
        public const val ISSUER: Long = 1

        /**
         * The key of `sub`.
         *
         * @since 1.0.0
         */
        public const val SUBJECT: Long = 2

        /**
         * The key of `aud`.
         *
         * @since 1.0.0
         */
        public const val AUDIENCE: Long = 3

        /**
         * The key of `exp`.
         *
         * @since 1.0.0
         */
        public const val EXPIRATION: Long = 4

        /**
         * The key of `nbf`.
         *
         * @since 1.0.0
         */
        public const val NOT_BEFORE: Long = 5

        /**
         * The key of `iat`.
         *
         * @since 1.0.0
         */
        public const val ISSUED_AT: Long = 6

        /**
         * The key of `cti`.
         *
         * @since 1.0.0
         */
        public const val CWT_ID: Long = 7

        private val RULES: Map<Long, (CborItem) -> Boolean> = mapOf(
            ISSUER to { value -> value.textOrNull() != null },
            SUBJECT to { value -> value.textOrNull() != null },
            AUDIENCE to { value -> isAudience(value) },
            EXPIRATION to { value -> NumericDates.of(value) != null },
            NOT_BEFORE to { value -> NumericDates.of(value) != null },
            ISSUED_AT to { value -> NumericDates.of(value) != null },
            CWT_ID to { value -> value.bytesOrNull() != null },
        )

        /**
         * Returns the claims set of [claims].
         *
         * @param claims the claims.
         * @return the claims set.
         * @throws IllegalArgumentException if a key is neither an integer nor a text or a registered claim has the
         *   wrong type.
         * @since 1.0.0
         */
        public fun of(claims: CborMap): CwtClaims {
            require(isValid(claims)) { "The claims have keys and values of their types" }
            return CwtClaims(claims)
        }

        /**
         * Returns a claims set of the registered claims and [others].
         *
         * A time with a fraction of a second is written as a float, every other time as an integer.
         *
         * @param issuer the `iss`, or null.
         * @param subject the `sub`, or null.
         * @param audience the `aud`: none by default, one written as a text, several as an array.
         * @param expiration the `exp`, or null.
         * @param notBefore the `nbf`, or null.
         * @param issuedAt the `iat`, or null.
         * @param cwtId the `cti`, or null.
         * @param others further claims, whose keys must differ from the registered ones given.
         * @return the claims set.
         * @throws IllegalArgumentException if a key is given twice or a claim has the wrong type.
         * @since 1.0.0
         */
        public fun of(
            issuer: String? = null,
            subject: String? = null,
            audience: List<String> = emptyList(),
            expiration: Instant? = null,
            notBefore: Instant? = null,
            issuedAt: Instant? = null,
            cwtId: ByteString? = null,
            others: CborMap = CborMap.Empty,
        ): CwtClaims {
            val audiences = audience.map { entry -> CborText(entry) }
            val registered = listOf(
                ISSUER to issuer?.let { text -> CborText(text) },
                SUBJECT to subject?.let { text -> CborText(text) },
                AUDIENCE to (audiences.singleOrNull() ?: CborArray(audiences).takeIf { audiences.isNotEmpty() }),
                EXPIRATION to expiration?.let { instant -> NumericDates.itemOf(instant) },
                NOT_BEFORE to notBefore?.let { instant -> NumericDates.itemOf(instant) },
                ISSUED_AT to issuedAt?.let { instant -> NumericDates.itemOf(instant) },
                CWT_ID to cwtId?.let { bytes -> CborBytes(bytes) },
            )
            val given = registered.mapNotNull { (key, value) -> value?.let { found -> labelOf(key) to found } }
            return of(CborMap(given + others.entries))
        }

        internal fun ofOrNull(claims: CborMap): CwtClaims? = CwtClaims(claims).takeIf { isValid(claims) }

        private fun isValid(claims: CborMap): Boolean = claims.entries.all { (key, value) ->
            val rule = key.longOrNull()?.let { number -> RULES[number] } ?: { true }
            HeaderRules.isLabel(key) && rule(value)
        }

        private fun isAudience(value: CborItem): Boolean {
            val entries = value.itemsOrNull().orEmpty()
            val isArray = entries.isNotEmpty() && entries.all { entry -> entry.textOrNull() != null }
            return value.textOrNull() != null || isArray
        }
    }
}
