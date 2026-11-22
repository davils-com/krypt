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

package com.davils.krypt.jose

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.core.SecretText
import com.davils.krypt.jose.jwk.KeyOperation
import com.davils.krypt.jose.jwk.KeyUse
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey

private const val NO_ID: String = "none"

private fun usageOf(key: JoseKey): String {
    val use = key.use?.let { found -> ", use=${found.useName}" }.orEmpty()
    val operations = key.operations.takeIf { found -> found.isNotEmpty() }
    val named = operations?.let { found -> ", key_ops=${found.map { operation -> operation.operationName }}" }.orEmpty()
    val algorithm = key.algorithm?.let { found -> ", alg=${SafeText.text(found)}" }.orEmpty()
    return use + named + algorithm
}

/**
 * A key that signs, verifies, encrypts or decrypts a JOSE message, with the key id it goes by.
 *
 * A key with a [keyId] is only tried for a message whose `kid` is absent or equal; a key without one is tried for
 * every message whose algorithm it fits. A key that declares a [use], [operations] or an [algorithm], as one read
 * from a JWK does, is only used where they fit, as RFC 8725 section 3.1 asks: a key of use `enc` never verifies a
 * signature, a key of `alg` `PS256` never verifies an `RS256` one. Where a key does not fit, verification and
 * decryption try the next key and creation throws. A message never chooses its own key: keys embedded in a header,
 * such as `jwk` or `x5c`, are never trusted by themselves.
 *
 * @since 1.0.0
 */
public sealed interface JoseKey {
    /**
     * The key id, matched against the `kid` header, or null.
     *
     * @since 1.0.0
     */
    public val keyId: String?

    /**
     * The use the key is limited to, from the `use` member of its JWK, or null for any use.
     *
     * @since 1.0.0
     */
    public val use: KeyUse? get() = null

    /**
     * The operations the key is limited to, from the `key_ops` member of its JWK, or empty for any operation.
     *
     * @since 1.0.0
     */
    public val operations: Set<KeyOperation> get() = emptySet()

    /**
     * The name of the only algorithm the key is for, such as `ES256` or `RSA-OAEP-256`, from the `alg` member of its
     * JWK, or null for any algorithm that fits the key. A key of a JWE with direct encryption may name `dir` or its
     * content encryption.
     *
     * @since 1.0.0
     */
    public val algorithm: String? get() = null

    /**
     * A public key, which verifies signatures and encrypts to its owner.
     *
     * @property key the key.
     * @property keyId the key id, or null.
     * @property use the use the key is limited to, or null.
     * @param operations the operations the key is limited to, or empty.
     * @property algorithm the only algorithm the key is for, or null.
     * @since 1.0.0
     */
    public class Public(
        public val key: PublicKey,
        override val keyId: String? = null,
        override val use: KeyUse? = null,
        operations: Set<KeyOperation> = emptySet(),
        override val algorithm: String? = null,
    ) : JoseKey {
        override val operations: Set<KeyOperation> = operations.toSet()

        private val values: List<Any?> get() = listOf(key, keyId, use, this.operations, algorithm)

        /**
         * Compares the key, the id and the limits of its use.
         *
         * @param other the other object.
         * @return true if [other] is the same key with the same id and limits.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Public && values == other.values

        /**
         * Hashes the key, the id and the limits of its use.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = values.hashCode()

        /**
         * Shows the key, the id and the limits of its use.
         *
         * @return the key as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Public($key, kid=${SafeText.text(keyId ?: NO_ID)}${usageOf(this)})"
    }

    /**
     * A private key, which signs and decrypts.
     *
     * @property key the key.
     * @property keyId the key id, or null.
     * @property use the use the key is limited to, or null.
     * @param operations the operations the key is limited to, or empty.
     * @property algorithm the only algorithm the key is for, or null.
     * @since 1.0.0
     */
    public class Private(
        public val key: PrivateKey,
        override val keyId: String? = null,
        override val use: KeyUse? = null,
        operations: Set<KeyOperation> = emptySet(),
        override val algorithm: String? = null,
    ) : JoseKey {
        override val operations: Set<KeyOperation> = operations.toSet()

        private val values: List<Any?> get() = listOf(key, keyId, use, this.operations, algorithm)

        /**
         * Compares the key by identity, the id and the limits of its use.
         *
         * @param other the other object.
         * @return true if [other] holds the same key object with the same id and limits.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Private && values == other.values

        /**
         * Hashes the key, the id and the limits of its use.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = values.hashCode()

        /**
         * Shows the kind of the key, the id and the limits of its use, never the key.
         *
         * @return the key as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Private($key, kid=${SafeText.text(keyId ?: NO_ID)}${usageOf(this)})"
    }

    /**
     * A symmetric key: an HMAC key of a JWS, or a key-wrapping or direct key of a JWE.
     *
     * @property key the key.
     * @property keyId the key id, or null.
     * @property use the use the key is limited to, or null.
     * @param operations the operations the key is limited to, or empty.
     * @property algorithm the only algorithm the key is for, or null.
     * @since 1.0.0
     */
    public class Secret(
        public val key: SecretKey,
        override val keyId: String? = null,
        override val use: KeyUse? = null,
        operations: Set<KeyOperation> = emptySet(),
        override val algorithm: String? = null,
    ) : JoseKey {
        override val operations: Set<KeyOperation> = operations.toSet()

        private val values: List<Any?> get() = listOf(key, keyId, use, this.operations, algorithm)

        /**
         * Compares the key in constant time, the id and the limits of its use.
         *
         * @param other the other object.
         * @return true if [other] holds the same key bytes with the same id and limits.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Secret && values == other.values

        /**
         * Hashes the size of the key and the id.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = values.hashCode()

        /**
         * Shows the size of the key, the id and the limits of its use, never the key.
         *
         * @return the key as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Secret($key, kid=${SafeText.text(keyId ?: NO_ID)}${usageOf(this)})"
    }

    /**
     * A password of PBES2, which [com.davils.krypt.jose.jwe.Jwe] accepts only when it was created with
     * `isPasswordAllowed`.
     *
     * @property password the password; the caller owns it and destroys it.
     * @property keyId the key id, or null.
     * @since 1.0.0
     */
    public class Password(public val password: SecretText, override val keyId: String? = null) : JoseKey {
        /**
         * Compares the password in constant time and the id.
         *
         * @param other the other object.
         * @return true if [other] holds the same password with the same id.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean =
            other is Password && password == other.password && keyId == other.keyId

        /**
         * Hashes the length of the password and the id.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = listOf(password, keyId).hashCode()

        /**
         * Shows the id, never the password.
         *
         * @return the key as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Password(${SafeText.REDACTED}, kid=${SafeText.text(keyId ?: NO_ID)})"
    }
}
