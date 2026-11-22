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

package com.davils.krypt.jose.jwt

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.kore.core.validation.inRange
import com.davils.krypt.jose.jwe.JweAlgorithm
import com.davils.krypt.jose.jwe.JweEncryption
import com.davils.krypt.jose.jws.JwsAlgorithm
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

private const val SUBJECT: String = "jwtValidator"
private const val NONE: String = "none"

/**
 * How [Jwt.validate] checks a token, by the best current practice of RFC 8725. Build one with [jwtValidator].
 *
 * @since 1.0.0
 */
public class JwtValidator internal constructor(builder: JwtValidatorBuilder) : Validatable {
    /**
     * The signature algorithms a token may use; required unless [isSignatureRequired] is false.
     *
     * @since 1.0.0
     */
    public val algorithms: Set<JwsAlgorithm> = builder.algorithms.toSet()

    /**
     * The key management algorithms an encrypted token may use; empty to refuse encryption.
     *
     * @since 1.0.0
     */
    public val keyAlgorithms: Set<JweAlgorithm> = builder.keyAlgorithms.toSet()

    /**
     * The content encryptions an encrypted token may use.
     *
     * @since 1.0.0
     */
    public val encryptions: Set<JweEncryption> = builder.encryptions.toSet()

    /**
     * The expected `typ`, such as `at+jwt`, compared without case and without the `application/` prefix; null to accept
     * any.
     *
     * @since 1.0.0
     */
    public val type: String? = builder.type

    /**
     * The expected `iss`, or null to accept any.
     *
     * @since 1.0.0
     */
    public val issuer: String? = builder.issuer

    /**
     * The audiences the caller identifies with; a token must name one of them, and a token with an `aud` is refused if
     * this is empty.
     *
     * @since 1.0.0
     */
    public val audiences: Set<String> = builder.audiences.toSet()

    /**
     * The tolerance of every time comparison, 0 to 1 day.
     *
     * @since 1.0.0
     */
    public val clockSkew: Duration = builder.clockSkew

    /**
     * The oldest `iat` accepted, or null for no limit; a token without `iat` is refused if set.
     *
     * @since 1.0.0
     */
    public val maximumAge: Duration? = builder.maximumAge

    /**
     * The claims a token must carry.
     *
     * @since 1.0.0
     */
    public val requiredClaims: Set<String> = builder.requiredClaims.toSet()

    /**
     * Whether a token must carry `exp`.
     *
     * @since 1.0.0
     */
    public val isExpirationRequired: Boolean = builder.isExpirationRequired

    /**
     * Whether an encrypted token must also be signed (a nested JWT); anyone who knows a public key can encrypt to it,
     * so encryption alone authenticates nobody.
     *
     * @since 1.0.0
     */
    public val isSignatureRequired: Boolean = builder.isSignatureRequired

    /**
     * The `crit` extensions the caller understands and processes itself.
     *
     * @since 1.0.0
     */
    public val critical: Set<String> = builder.critical.toSet()

    private val values: List<Any?>
        get() = listOf(
            algorithms,
            keyAlgorithms,
            encryptions,
            type,
            issuer,
            audiences,
            clockSkew,
            maximumAge,
            requiredClaims,
            isExpirationRequired,
            isSignatureRequired,
            critical,
        )

    /**
     * Checks the skew, the age and that a signed token has an algorithm.
     *
     * @since 1.0.0
     */
    override fun ValidationScope.validate() {
        inRange(property = ::clockSkew, value = clockSkew, range = Duration.ZERO..MAXIMUM_SKEW)
        val age = maximumAge
        if (age != null && !age.isPositive()) fail(::maximumAge, "A maximum age is positive")
        if (isSignatureRequired && algorithms.isEmpty()) fail(::algorithms, "A signed token needs an algorithm")
        if (keyAlgorithms.isNotEmpty() && encryptions.isEmpty()) {
            fail(::encryptions, "An encrypted token needs a content encryption")
        }
    }

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] checks the same.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is JwtValidator && values == other.values

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the checks.
     *
     * @return the validator as text.
     * @since 1.0.0
     */
    override fun toString(): String = "JwtValidator(algorithms=${algorithms.map { found -> found.algorithmName }}, " +
        "type=${SafeText.text(type ?: NONE)}, issuer=${SafeText.text(issuer ?: NONE)}, " +
        "audiences=${audiences.size}, skew=$clockSkew, maximumAge=${maximumAge ?: NONE}, signatureRequired=$isSignatureRequired)"

    /**
     * The bounds of a validator.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The largest clock skew: one day.
         *
         * @since 1.0.0
         */
        public val MAXIMUM_SKEW: Duration = 1.days

        internal const val NAME: String = SUBJECT
    }
}
