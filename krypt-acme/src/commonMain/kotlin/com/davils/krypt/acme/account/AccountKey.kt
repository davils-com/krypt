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

package com.davils.krypt.acme.account

import com.davils.krypt.acme.internal.SigningAlgorithms
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey

/**
 * The key pair of an ACME account, or of a certificate to revoke, with the JWS algorithm it signs requests with.
 *
 * RFC 8555 forbids MAC algorithms for requests: the algorithm is RSA (`RS256` to `PS512`), ECDSA (`ES256` to
 * `ES512`, on the curve the algorithm names) or EdDSA. The key is a handle, which may be non-extractable; the
 * caller destroys it. Values are immutable and safe to share between threads.
 *
 * @property privateKey the private key, whose public key is known.
 * @property algorithm the signature algorithm; [defaultAlgorithm] of the key by default.
 * @constructor Checks that the algorithm fits the key.
 * @throws IllegalArgumentException if the public key of [privateKey] is unknown or [algorithm] does not fit it.
 * @since 1.0.0
 */
public class AccountKey(
    public val privateKey: PrivateKey,
    public val algorithm: JwsAlgorithm = defaultAlgorithm(privateKey),
) {
    /**
     * The public key of [privateKey].
     *
     * @since 1.0.0
     */
    public val publicKey: PublicKey = requireNotNull(privateKey.publicKey) { "An account key needs its public key" }

    init {
        require(SigningAlgorithms.fits(algorithm = algorithm, key = publicKey)) {
            "${algorithm.algorithmName} does not sign with this key"
        }
    }

    /**
     * Compares the key and the algorithm.
     *
     * @param other the other object.
     * @return true if [other] is the same key with the same algorithm.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is AccountKey && privateKey == other.privateKey && algorithm == other.algorithm

    /**
     * Hashes the public key and the algorithm.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(publicKey, algorithm).hashCode()

    /**
     * Shows the algorithm, never the key.
     *
     * @return the key as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AccountKey(${algorithm.algorithmName})"

    /**
     * Picks algorithms for keys.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the algorithm ACME servers accept most widely for [key]: `RS256` for RSA, `ES256`, `ES384` or
         * `ES512` for the NIST curves and `EdDSA` for Ed25519 and Ed448.
         *
         * @param key the private key.
         * @return the algorithm.
         * @throws IllegalArgumentException if the key does not sign by JOSE, as an X25519 or ML-KEM key.
         * @since 1.0.0
         */
        public fun defaultAlgorithm(key: PrivateKey): JwsAlgorithm =
            requireNotNull(SigningAlgorithms.defaultFor(family = key.family, curve = key.curve)) {
                "A ${key.family} key does not sign ACME requests"
            }
    }
}
