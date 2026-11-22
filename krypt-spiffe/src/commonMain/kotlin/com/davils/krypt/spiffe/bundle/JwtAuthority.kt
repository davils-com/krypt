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

package com.davils.krypt.spiffe.bundle

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.primitive.key.PublicKey

/**
 * A JWT authority of a trust domain: a key that signs JWT-SVIDs and its key id, the `kid` the tokens name.
 *
 * Immutable and safe to share between threads.
 *
 * @property keyId the key id, 1 to [MAXIMUM_KEY_ID_LENGTH] characters.
 * @property publicKey the public key.
 * @constructor Checks the key id.
 * @throws IllegalArgumentException if [keyId] is empty or longer than [MAXIMUM_KEY_ID_LENGTH].
 * @since 1.0.0
 */
public class JwtAuthority(public val keyId: String, public val publicKey: PublicKey) {
    init {
        require(keyId.length in 1..MAXIMUM_KEY_ID_LENGTH) { "A key id has 1 to $MAXIMUM_KEY_ID_LENGTH characters" }
    }

    /**
     * Compares the key id and the key.
     *
     * @param other the other object.
     * @return true if [other] is the same authority.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is JwtAuthority && keyId == other.keyId && publicKey == other.publicKey

    /**
     * Hashes the key id and the key.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(keyId, publicKey).hashCode()

    /**
     * Shows the key id and the key.
     *
     * @return the authority as text.
     * @since 1.0.0
     */
    override fun toString(): String = "JwtAuthority(kid=${SafeText.text(keyId)}, $publicKey)"

    /**
     * The bounds of an authority.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The longest key id.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_KEY_ID_LENGTH: Int = 1_024
    }
}
