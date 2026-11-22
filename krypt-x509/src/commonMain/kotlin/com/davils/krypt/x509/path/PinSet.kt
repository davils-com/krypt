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

package com.davils.krypt.x509.path

import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

private const val PIN_BYTES: Int = 32

/**
 * A set of public key pins: SHA-256 digests of the public keys a path must contain, as in HTTP public key pinning.
 *
 * Pin the key of an authority and a backup key, not only the key of a server, so that a key change does not lock
 * clients out.
 *
 * @property pins the SHA-256 digests of the DER encodings of the public keys.
 * @constructor Holds [pins].
 * @throws IllegalArgumentException if [pins] is empty or a pin is not 32 bytes.
 * @since 1.0.0
 */
public class PinSet(public val pins: Set<ByteString>) {
    init {
        require(pins.isNotEmpty() && pins.all { pin -> pin.size == PIN_BYTES }) { "A pin set holds pins of 32 bytes" }
    }

    /**
     * Tells whether a certificate of [path] or the anchor carries a pinned key.
     *
     * @param crypto the primitives.
     * @param path a validated path.
     * @return true if a key of the path is pinned.
     * @since 1.0.0
     */
    public suspend fun matches(crypto: Crypto, path: PathValidation.Valid): Boolean {
        val keys = path.path.map { certificate -> certificate.subjectPublicKeyInfo } + path.anchor.publicKey.encoded
        return keys.any { key -> crypto.digests.digest(key, DigestAlgorithm.Sha256) in pins }
    }

    /**
     * Compares the pins.
     *
     * @param other the other object.
     * @return true if [other] holds the same pins.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is PinSet && pins == other.pins

    /**
     * Hashes the pins.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = pins.hashCode()

    /**
     * Shows the pins in hex.
     *
     * @return the set as text.
     * @since 1.0.0
     */
    override fun toString(): String = "PinSet(${pins.map { pin -> Hex.encode(pin) }.sorted()})"

    /**
     * Creating pin sets.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the pins of the public keys of [certificates].
         *
         * @param crypto the primitives.
         * @param certificates the certificates whose keys to pin; at least one.
         * @return the pin set.
         * @since 1.0.0
         */
        public suspend fun of(crypto: Crypto, certificates: List<Certificate>): PinSet {
            val pins = certificates.map { certificate ->
                crypto.digests.digest(
                    certificate.subjectPublicKeyInfo,
                    DigestAlgorithm.Sha256,
                )
            }
            return PinSet(pins.toSet())
        }
    }
}
