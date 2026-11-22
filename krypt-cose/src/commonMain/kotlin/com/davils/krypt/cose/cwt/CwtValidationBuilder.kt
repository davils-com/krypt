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

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.kore.core.dsl.ValidatingBuilder
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseMessageType
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborItem
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Builds a [CwtValidation]. Nothing is accepted until [algorithms] names at least one algorithm.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class CwtValidationBuilder internal constructor() : ValidatingBuilder<CwtValidation>() {
    override val subject: String get() = "cwtValidation"

    internal val accepted: MutableSet<CoseAlgorithm> = linkedSetOf()

    internal val required: MutableSet<CborItem> = linkedSetOf()

    /**
     * See [CwtValidation.issuer].
     *
     * @since 1.0.0
     */
    public var issuer: String? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CwtValidation.audience].
     *
     * @since 1.0.0
     */
    public var audience: String? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CwtValidation.skew]; 5 minutes by default.
     *
     * @since 1.0.0
     */
    public var skew: Duration = DEFAULT_SKEW_MINUTES.minutes
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CwtValidation.at].
     *
     * @since 1.0.0
     */
    public var at: Instant? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CwtValidation.untaggedType].
     *
     * @since 1.0.0
     */
    public var untaggedType: CoseMessageType? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * Accepts [algorithms] for every COSE layer of the CWT, in addition to the ones accepted already.
     *
     * @param algorithms the algorithms: signature, MAC, content encryption and key distribution algorithms alike.
     * @throws IllegalStateException if this builder was evaluated already.
     * @since 1.0.0
     */
    public fun algorithms(vararg algorithms: CoseAlgorithm) {
        checkOpen()
        accepted += algorithms
    }

    /**
     * Requires the claims with the integer keys [keys], such as [CwtClaims.EXPIRATION].
     *
     * @param keys the keys.
     * @throws IllegalStateException if this builder was evaluated already.
     * @since 1.0.0
     */
    public fun require(vararg keys: Long) {
        checkOpen()
        required += keys.map { key -> CborInteger.of(key) }
    }

    /**
     * Requires the claim with [key], an integer or a text.
     *
     * @param key the key.
     * @throws IllegalStateException if this builder was evaluated already.
     * @since 1.0.0
     */
    public fun require(key: CborItem) {
        checkOpen()
        required += key
    }

    override fun assemble(): CwtValidation = CwtValidation(this)

    private companion object {
        const val DEFAULT_SKEW_MINUTES: Int = 5
    }
}
