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

package com.davils.krypt.keyset

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.keyset.internal.KeyTypes
import com.davils.krypt.primitive.exchange.HpkeSuite

/**
 * What the keys of a [Keyset] are for; every key of a key set has the same purpose.
 *
 * @since 1.0.0
 */
public sealed class KeyPurpose {
    /**
     * The type of the key pairs of an asymmetric purpose, or null for symmetric keys.
     *
     * @since 1.0.0
     */
    public abstract val keyType: KeyType?

    internal abstract val secretBytes: Int

    /**
     * Authenticated encryption with symmetric keys of [algorithm].
     *
     * @property algorithm the AEAD.
     * @constructor Encrypts with [algorithm].
     * @since 1.0.0
     */
    public class Aead(public val algorithm: AeadAlgorithm = AeadAlgorithm.Aes256Gcm) : KeyPurpose() {
        override val keyType: KeyType? get() = null

        override val secretBytes: Int get() = algorithm.keyBytes

        /**
         * Compares the algorithm.
         *
         * @param other the other object.
         * @return true if [other] is the same purpose.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Aead && algorithm == other.algorithm

        /**
         * Hashes the algorithm.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = algorithm.hashCode()

        /**
         * Shows the algorithm.
         *
         * @return the purpose as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Aead(${algorithm.algorithmName})"
    }

    /**
     * Message authentication with symmetric keys of [algorithm], also the root of derived keys and blind indexes.
     *
     * @property algorithm the MAC.
     * @constructor Authenticates with [algorithm].
     * @since 1.0.0
     */
    public class Mac(public val algorithm: MacAlgorithm = MacAlgorithm.HmacSha256) : KeyPurpose() {
        override val keyType: KeyType? get() = null

        override val secretBytes: Int get() = algorithm.tagBytes

        /**
         * Compares the algorithm.
         *
         * @param other the other object.
         * @return true if [other] is the same purpose.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Mac && algorithm == other.algorithm

        /**
         * Hashes the algorithm.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = algorithm.hashCode()

        /**
         * Shows the algorithm.
         *
         * @return the purpose as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Mac(${algorithm.algorithmName})"
    }

    /**
     * Digital signatures with key pairs of [type], with the default signature algorithm of the key.
     *
     * @property type the type of the key pairs.
     * @constructor Signs with keys of [type].
     * @throws IllegalArgumentException if keys of [type] do not sign.
     * @since 1.0.0
     */
    public class Signing(public val type: KeyType = KeyType.Ed25519) : KeyPurpose() {
        override val keyType: KeyType get() = type

        override val secretBytes: Int get() = 0

        init {
            require(type in KeyTypes.SIGNING) { "A key of $type does not sign" }
        }

        /**
         * Compares the key type.
         *
         * @param other the other object.
         * @return true if [other] is the same purpose.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Signing && type == other.type

        /**
         * Hashes the key type.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = type.hashCode()

        /**
         * Shows the key type.
         *
         * @return the purpose as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Signing($type)"
    }

    /**
     * Hybrid public key encryption of RFC 9180 with [suite], whose KEM decides the type of the key pairs.
     *
     * @property suite the cipher suite, which must have an AEAD.
     * @constructor Encrypts to keys of [suite].
     * @throws IllegalArgumentException if [suite] exports only.
     * @since 1.0.0
     */
    public class Hybrid(public val suite: HpkeSuite = HpkeSuite.X25519Aes256Gcm) : KeyPurpose() {
        override val keyType: KeyType = KeyTypes.ofKem(suite.kem)

        override val secretBytes: Int get() = 0

        internal val aead: AeadAlgorithm = requireNotNull(suite.aead) { "An export-only suite encrypts nothing" }

        /**
         * Compares the suite.
         *
         * @param other the other object.
         * @return true if [other] is the same purpose.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Hybrid && suite == other.suite

        /**
         * Hashes the suite.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = suite.hashCode()

        /**
         * Shows the suite.
         *
         * @return the purpose as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Hybrid($suite)"
    }
}
