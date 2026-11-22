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

package com.davils.krypt.jose.jwt

import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.internal.ClaimNames
import com.davils.krypt.jose.internal.audienceOf
import com.davils.krypt.jose.internal.instantOf
import com.davils.krypt.jose.internal.textOf
import kotlin.time.Instant

/**
 * The claims set of a JSON Web Token of RFC 7519.
 *
 * The registered claims are typed: `iss`, `sub` and `jti` are texts, `aud` is a text or an array of texts, and
 * `exp`, `nbf` and `iat` are NumericDates in whole seconds. Every other claim is a [JsonValue]. Build claims with
 * [jwtClaims]; read them from a token with [Jwt.validate].
 *
 * @property members every claim.
 * @since 1.0.0
 */
public class JwtClaims internal constructor(public val members: JsonValue.Object) : Validatable {
    /**
     * The `iss` claim.
     *
     * @since 1.0.0
     */
    public val issuer: String? get() = members.textOf(ClaimNames.ISSUER)

    /**
     * The `sub` claim.
     *
     * @since 1.0.0
     */
    public val subject: String? get() = members.textOf(ClaimNames.SUBJECT)

    /**
     * The `aud` claim as a list, empty if absent.
     *
     * @since 1.0.0
     */
    public val audience: List<String> get() = members.audienceOf()

    /**
     * The `exp` claim.
     *
     * @since 1.0.0
     */
    public val expiresAt: Instant? get() = members.instantOf(ClaimNames.EXPIRES_AT)

    /**
     * The `nbf` claim.
     *
     * @since 1.0.0
     */
    public val notBefore: Instant? get() = members.instantOf(ClaimNames.NOT_BEFORE)

    /**
     * The `iat` claim.
     *
     * @since 1.0.0
     */
    public val issuedAt: Instant? get() = members.instantOf(ClaimNames.ISSUED_AT)

    /**
     * The `jti` claim.
     *
     * @since 1.0.0
     */
    public val jwtId: String? get() = members.textOf(ClaimNames.JWT_ID)

    /**
     * Returns the claim [name].
     *
     * @param name the claim name.
     * @return the value, or null if absent.
     * @since 1.0.0
     */
    public operator fun get(name: String): JsonValue? = members[name]

    /**
     * Writes the claims as compact JSON.
     *
     * @return the JSON text.
     * @since 1.0.0
     */
    public fun encode(): String = members.encode()

    /**
     * Checks that a token is not valid before it was issued and not after it expires.
     *
     * @since 1.0.0
     */
    override fun ValidationScope.validate() {
        val start = notBefore ?: issuedAt
        val end = expiresAt
        if (start != null && end != null && end < start) fail(::expiresAt, "A token expires after it becomes valid")
    }

    /**
     * Compares the claims.
     *
     * @param other the other object.
     * @return true if [other] holds the same claims.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is JwtClaims && members == other.members

    /**
     * Hashes the claims.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = members.hashCode()

    /**
     * Shows the claim names, never their values.
     *
     * @return the claims as text.
     * @since 1.0.0
     */
    override fun toString(): String = "JwtClaims($members)"
}
