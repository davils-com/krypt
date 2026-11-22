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

package com.davils.krypt.cose.cwt

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.kore.core.validation.atMost
import com.davils.kore.core.validation.nonNegative
import com.davils.kore.core.validation.notEmpty
import com.davils.kore.core.validation.validateOrThrow
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseMessageType
import com.davils.krypt.cose.cbor.CborItem
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

private const val SUBJECT: String = "cwtValidation"

/**
 * How a CWT is validated by RFC 8392 section 7.2: which algorithms its COSE layers may use, which issuer and audience
 * it must name, which claims it must carry and how far the clocks may differ.
 *
 * Build one with [cwtValidation]. The checks of time apply only to the claims present: a CWT without `exp` never
 * expires unless [requiredClaims] demands it.
 *
 * @since 1.0.0
 */
public class CwtValidation internal constructor(builder: CwtValidationBuilder) : Validatable {
    /**
     * The algorithms every COSE layer of the CWT may use, at least one.
     *
     * @since 1.0.0
     */
    public val algorithms: Set<CoseAlgorithm> = builder.accepted.toSet()

    /**
     * The issuer the `iss` claim must equal, or null for any issuer.
     *
     * @since 1.0.0
     */
    public val issuer: String? = builder.issuer

    /**
     * The audience the `aud` claim must name, or null for any audience.
     *
     * @since 1.0.0
     */
    public val audience: String? = builder.audience

    /**
     * How far the clocks of the issuer and the validator may differ, from zero to [MAXIMUM_SKEW].
     *
     * @since 1.0.0
     */
    public val skew: Duration = builder.skew

    /**
     * The time of validation, or null for the clock of the environment.
     *
     * @since 1.0.0
     */
    public val at: Instant? = builder.at

    /**
     * The type of an untagged CWT, or null to accept only CWTs with a COSE tag.
     *
     * @since 1.0.0
     */
    public val untaggedType: CoseMessageType? = builder.untaggedType

    /**
     * The keys of the claims the CWT must carry.
     *
     * @since 1.0.0
     */
    public val requiredClaims: Set<CborItem> = builder.required.toSet()

    /**
     * Whether a layer of the CWT must authenticate its issuer; true by default. Such a layer is a signature, a MAC or
     * a content encryption whose key the validator shares with the issuer in advance (a COSE_Encrypt0, or a
     * COSE_Encrypt with a direct or key wrap recipient), each verified with one of the keys of the validator. A
     * COSE_Encrypt or COSE_Mac whose key came from an ECDH-ES recipient never counts: anyone who knows the public key
     * of the recipient can create one, so it hides the claims but says nothing about who wrote them. A CWT without
     * such a layer is refused with [CwtFailure.Unauthenticated].
     *
     * Turn it off only when the claims need no origin, for example when the application authenticates the issuer
     * through another channel; the claims of an unauthenticated CWT may otherwise come from anyone.
     *
     * @since 1.0.0
     */
    public val isAuthenticationRequired: Boolean = builder.isAuthenticationRequired

    private val values: List<Any?>
        get() = listOf(algorithms, issuer, audience, skew, at, untaggedType, requiredClaims, isAuthenticationRequired)

    init {
        validateOrThrow(SUBJECT)
    }

    /**
     * Checks that an algorithm is accepted and the skew is in range.
     *
     * @receiver the validation that collects the violations.
     * @since 1.0.0
     */
    override fun ValidationScope.validate() {
        notEmpty(property = ::algorithms, items = algorithms)
        nonNegative(property = ::skew, value = skew)
        atMost(property = ::skew, value = skew, maximum = MAXIMUM_SKEW)
    }

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] validates alike.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CwtValidation && values == other.values

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows every property, escaping the issuer and the audience.
     *
     * @return the validation as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CwtValidation(algorithms=$algorithms, issuer=${quoted(issuer)}, " +
        "audience=${quoted(audience)}, skew=$skew, at=${at ?: CLOCK}, untaggedType=${untaggedType ?: NONE}, " +
        "requiredClaims=$requiredClaims, authenticationRequired=$isAuthenticationRequired)"

    /**
     * The bound of the skew.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The largest skew: one hour.
         *
         * @since 1.0.0
         */
        public val MAXIMUM_SKEW: Duration = 1.hours

        private const val CLOCK: String = "clock"
        private const val NONE: String = "none"

        private fun quoted(text: String?): String {
            if (text == null) return NONE
            return "\"${SafeText.text(text)}\""
        }
    }
}
