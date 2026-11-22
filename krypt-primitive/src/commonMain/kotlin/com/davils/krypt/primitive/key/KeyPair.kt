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

package com.davils.krypt.primitive.key

/**
 * A private key and the public key that belongs to it.
 *
 * @property publicKey the public key.
 * @property privateKey the private key.
 * @since 1.0.0
 */
public class KeyPair(public val publicKey: PublicKey, public val privateKey: PrivateKey) {
    /**
     * Compares both keys.
     *
     * @param other the other object.
     * @return true if [other] holds the same keys.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is KeyPair && publicKey == other.publicKey && privateKey == other.privateKey

    /**
     * Hashes the public key.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = publicKey.hashCode()

    /**
     * Shows the public key, never the private key.
     *
     * @return the pair as text.
     * @since 1.0.0
     */
    override fun toString(): String = "KeyPair($publicKey)"
}
