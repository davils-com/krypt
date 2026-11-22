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

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.kore.core.dsl.ValidatingBuilder
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.internal.ClaimNames
import kotlin.time.Instant

/**
 * Builds [JwtClaims]. Dates are written as NumericDates in whole seconds, a single audience as a text and several as
 * an array.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class JwtClaimsBuilder internal constructor() : ValidatingBuilder<JwtClaims>() {
    override val subject: String get() = "jwtClaims"

    private val extra = ArrayList<Pair<String, JsonValue>>()

    /**
     * See [JwtClaims.issuer].
     *
     * @since 1.0.0
     */
    public var issuer: String? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * The `sub` claim, see [JwtClaims.subject]; named so because a builder of Kore names its own subject.
     *
     * @since 1.0.0
     */
    public var tokenSubject: String? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [JwtClaims.audience].
     *
     * @since 1.0.0
     */
    public var audience: List<String> = emptyList()
        set(value) {
            checkOpen()
            field = value.toList()
        }

    /**
     * See [JwtClaims.expiresAt].
     *
     * @since 1.0.0
     */
    public var expiresAt: Instant? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [JwtClaims.notBefore].
     *
     * @since 1.0.0
     */
    public var notBefore: Instant? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [JwtClaims.issuedAt].
     *
     * @since 1.0.0
     */
    public var issuedAt: Instant? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [JwtClaims.jwtId].
     *
     * @since 1.0.0
     */
    public var jwtId: String? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * Adds the claim [name] that is not registered by RFC 7519.
     *
     * @param name the claim name.
     * @param value the value.
     * @throws IllegalArgumentException if [name] is registered, such as `exp`, or was added before.
     * @since 1.0.0
     */
    public fun claim(name: String, value: JsonValue) {
        checkOpen()
        require(name !in ClaimNames.REGISTERED) { "A registered claim has its own property" }
        require(extra.none { (found, _) -> found == name }) { "A claim is added once" }
        extra += name to value
    }

    override fun assemble(): JwtClaims {
        val single = audience.singleOrNull()?.let { name -> JsonValue.Text(name) }
        val audienceValue = single ?: JsonValue.Array(audience.map { name -> JsonValue.Text(name) }).takeIf {
            audience.size > 1
        }
        val registered = listOfNotNull(
            issuer?.let { value -> ClaimNames.ISSUER to JsonValue.Text(value) },
            tokenSubject?.let { value -> ClaimNames.SUBJECT to JsonValue.Text(value) },
            audienceValue?.let { value -> ClaimNames.AUDIENCE to value },
            expiresAt?.let { value -> ClaimNames.EXPIRES_AT to JsonValue.Integer(value.epochSeconds) },
            notBefore?.let { value -> ClaimNames.NOT_BEFORE to JsonValue.Integer(value.epochSeconds) },
            issuedAt?.let { value -> ClaimNames.ISSUED_AT to JsonValue.Integer(value.epochSeconds) },
            jwtId?.let { value -> ClaimNames.JWT_ID to JsonValue.Text(value) },
        )
        return JwtClaims(JsonValue.Object(registered + extra))
    }
}
