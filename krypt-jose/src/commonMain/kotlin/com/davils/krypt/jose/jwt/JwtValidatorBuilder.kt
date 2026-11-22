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
import com.davils.krypt.jose.jwe.JweAlgorithm
import com.davils.krypt.jose.jwe.JweEncryption
import com.davils.krypt.jose.jws.JwsAlgorithm
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

private const val DEFAULT_SKEW_MINUTES: Int = 1

/**
 * Builds a [JwtValidator]. By default a token must be signed and carry `exp`, the skew is one minute, and nothing
 * else is checked; name the algorithms, the type, the issuer and the audience the application expects.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class JwtValidatorBuilder internal constructor() : ValidatingBuilder<JwtValidator>() {
    override val subject: String get() = JwtValidator.NAME

    internal val algorithms: MutableList<JwsAlgorithm> = ArrayList()
    internal val keyAlgorithms: MutableList<JweAlgorithm> = ArrayList()
    internal val encryptions: MutableList<JweEncryption> = ArrayList()
    internal val audiences: MutableList<String> = ArrayList()
    internal val requiredClaims: MutableList<String> = ArrayList()
    internal val critical: MutableList<String> = ArrayList()

    /**
     * See [JwtValidator.type].
     *
     * @since 1.0.0
     */
    public var type: String? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [JwtValidator.issuer].
     *
     * @since 1.0.0
     */
    public var issuer: String? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [JwtValidator.clockSkew].
     *
     * @since 1.0.0
     */
    public var clockSkew: Duration = DEFAULT_SKEW_MINUTES.minutes
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [JwtValidator.maximumAge].
     *
     * @since 1.0.0
     */
    public var maximumAge: Duration? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [JwtValidator.isExpirationRequired].
     *
     * @since 1.0.0
     */
    public var isExpirationRequired: Boolean = true
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [JwtValidator.isSignatureRequired].
     *
     * @since 1.0.0
     */
    public var isSignatureRequired: Boolean = true
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * Adds signature algorithms; see [JwtValidator.algorithms].
     *
     * @param permitted the algorithms.
     * @since 1.0.0
     */
    public fun algorithms(vararg permitted: JwsAlgorithm) {
        checkOpen()
        algorithms += permitted
    }

    /**
     * Adds key management algorithms and content encryptions of an encrypted token.
     *
     * @param algorithms the key management algorithms.
     * @param encryptions the content encryptions.
     * @since 1.0.0
     */
    public fun encryption(algorithms: Set<JweAlgorithm>, encryptions: Set<JweEncryption>) {
        checkOpen()
        keyAlgorithms += algorithms
        this.encryptions += encryptions
    }

    /**
     * Adds audiences; see [JwtValidator.audiences].
     *
     * @param names the audiences.
     * @since 1.0.0
     */
    public fun audience(vararg names: String) {
        checkOpen()
        audiences += names
    }

    /**
     * Adds required claims; see [JwtValidator.requiredClaims].
     *
     * @param names the claim names.
     * @since 1.0.0
     */
    public fun require(vararg names: String) {
        checkOpen()
        requiredClaims += names
    }

    /**
     * Adds understood `crit` extensions; see [JwtValidator.critical].
     *
     * @param names the extension names.
     * @since 1.0.0
     */
    public fun critical(vararg names: String) {
        checkOpen()
        critical += names
    }

    override fun assemble(): JwtValidator = JwtValidator(this)
}
