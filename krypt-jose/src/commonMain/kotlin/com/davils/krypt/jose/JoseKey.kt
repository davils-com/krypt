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
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey

private const val NO_ID: String = "none"

/**
 * A key that signs, verifies, encrypts or decrypts a JOSE message, with the key id it goes by.
 *
 * A key with a [keyId] is only tried for a message whose `kid` is absent or equal; a key without one is tried for
 * every message whose algorithm it fits. A message never chooses its own key: keys embedded in a header, such as
 * `jwk` or `x5c`, are never trusted by themselves.
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
     * A public key, which verifies signatures and encrypts to its owner.
     *
     * @property key the key.
     * @property keyId the key id, or null.
     * @since 1.0.0
     */
    public class Public(public val key: PublicKey, override val keyId: String? = null) : JoseKey {
        /**
         * Compares the key and the id.
         *
         * @param other the other object.
         * @return true if [other] is the same key with the same id.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Public && key == other.key && keyId == other.keyId

        /**
         * Hashes the key and the id.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = listOf(key, keyId).hashCode()

        /**
         * Shows the key and the id.
         *
         * @return the key as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Public($key, kid=${SafeText.text(keyId ?: NO_ID)})"
    }

    /**
     * A private key, which signs and decrypts.
     *
     * @property key the key.
     * @property keyId the key id, or null.
     * @since 1.0.0
     */
    public class Private(public val key: PrivateKey, override val keyId: String? = null) : JoseKey {
        /**
         * Compares the key by identity and the id.
         *
         * @param other the other object.
         * @return true if [other] holds the same key object with the same id.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Private && key == other.key && keyId == other.keyId

        /**
         * Hashes the key and the id.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = listOf(key, keyId).hashCode()

        /**
         * Shows the kind of the key and the id, never the key.
         *
         * @return the key as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Private($key, kid=${SafeText.text(keyId ?: NO_ID)})"
    }

    /**
     * A symmetric key: an HMAC key of a JWS, or a key-wrapping or direct key of a JWE.
     *
     * @property key the key.
     * @property keyId the key id, or null.
     * @since 1.0.0
     */
    public class Secret(public val key: SecretKey, override val keyId: String? = null) : JoseKey {
        /**
         * Compares the key in constant time and the id.
         *
         * @param other the other object.
         * @return true if [other] holds the same key bytes with the same id.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Secret && key == other.key && keyId == other.keyId

        /**
         * Hashes the size of the key and the id.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = listOf(key, keyId).hashCode()

        /**
         * Shows the size of the key and the id, never the key.
         *
         * @return the key as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Secret($key, kid=${SafeText.text(keyId ?: NO_ID)})"
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
