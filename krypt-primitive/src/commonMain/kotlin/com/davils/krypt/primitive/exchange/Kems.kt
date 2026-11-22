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

package com.davils.krypt.primitive.exchange

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.internal.Dhkem
import com.davils.krypt.primitive.internal.requireSupported
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString

private const val ML_KEM_1024_BITS: Int = 1_024

/**
 * Key encapsulation: the DHKEMs of RFC 9180 over X25519 and the NIST curves, and ML-KEM of FIPS 203 on the JVM.
 *
 * Encapsulating draws a fresh shared secret for the holder of a public key; only the holder of the private key can
 * decapsulate it. A failed decapsulation returns null; ML-KEM rejects implicitly and returns a pseudorandom secret
 * instead, so a wrong encapsulation shows itself only when the secret fails to decrypt.
 *
 * @since 1.0.0
 */
public class Kems internal constructor(private val crypto: Crypto) {
    /**
     * Encapsulates a fresh shared secret for [recipient].
     *
     * @param recipient the public key of the recipient.
     * @param algorithm the KEM; [defaultFor] the key by default.
     * @return the shared secret and the encapsulation.
     * @throws IllegalArgumentException if [algorithm] does not fit the key.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm].
     * @throws com.davils.krypt.primitive.UnsupportedAlgorithmException if the platform lacks [algorithm].
     * @throws com.davils.krypt.primitive.CryptoException if the platform refuses [recipient]; the exception carries
     *   nothing of the failure of the platform.
     * @since 1.0.0
     */
    public suspend fun encapsulate(
        recipient: PublicKey,
        algorithm: KemAlgorithm = defaultFor(
            recipient,
        ),
    ): Encapsulation {
        require(
            algorithm == defaultFor(recipient),
        ) { "${algorithm.algorithmName} does not encapsulate to a ${recipient.family} key" }
        crypto.permit(algorithm, AlgorithmUse.Protect)
        crypto.requireSupported(algorithm)
        return when (algorithm.family == KeyFamily.MlKem) {
            true -> mlKemEncapsulate(algorithm, recipient)
            false -> Dhkem(crypto, algorithm).encapsulate(recipient = recipient, sender = null)
        }
    }

    /**
     * Decapsulates [encapsulated] with [recipient].
     *
     * @param recipient the private key of the recipient, whose public key must be known for a DHKEM.
     * @param encapsulated the encapsulation.
     * @param algorithm the KEM.
     * @return the shared secret, or null if the encapsulation is malformed or the platform refuses it, such as a
     *   DHKEM point of small order or off the curve.
     * @throws IllegalArgumentException if [algorithm] does not fit the key.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm].
     * @throws com.davils.krypt.primitive.UnsupportedAlgorithmException if the platform lacks [algorithm].
     * @since 1.0.0
     */
    public suspend fun decapsulate(
        recipient: PrivateKey,
        encapsulated: ByteString,
        algorithm: KemAlgorithm,
    ): SecretBytes? {
        require(
            algorithm.family == recipient.family,
        ) { "${algorithm.algorithmName} does not decapsulate with a ${recipient.family} key" }
        crypto.permit(algorithm, AlgorithmUse.Verify)
        crypto.requireSupported(algorithm)
        return when (algorithm.family == KeyFamily.MlKem) {
            true -> mlKemDecapsulate(algorithm = algorithm, recipient = recipient, encapsulated = encapsulated)

            false -> Dhkem(
                crypto,
                algorithm,
            ).decapsulate(recipient = recipient, encapsulated = encapsulated, sender = null)
        }
    }

    /**
     * Picks the KEM for a recipient key.
     *
     * @param recipient the public key of the recipient.
     * @return the KEM.
     * @throws IllegalArgumentException if keys of its family do not encapsulate.
     * @since 1.0.0
     */
    public fun defaultFor(recipient: PublicKey): KemAlgorithm {
        val isLarge = recipient.bits == ML_KEM_1024_BITS
        val candidates = KemAlgorithm.entries.filter { kem -> kem.family == recipient.family }
        val chosen = candidates.firstOrNull { kem -> isDhkemFor(kem, recipient) }
            ?: candidates.firstOrNull { kem ->
                kem.family == KeyFamily.MlKem &&
                    kem == KemAlgorithm.MlKem1024 == isLarge
            }
        return requireNotNull(chosen) { "A ${recipient.family} key does not receive an encapsulation" }
    }

    private fun isDhkemFor(kem: KemAlgorithm, recipient: PublicKey): Boolean =
        kem.family != KeyFamily.MlKem && Dhkem.curveOf(kem) == recipient.curve

    private suspend fun mlKemDecapsulate(
        algorithm: KemAlgorithm,
        recipient: PrivateKey,
        encapsulated: ByteString,
    ): SecretBytes? {
        val secret = crypto.backend.decapsulate(algorithm, recipient, encapsulated.toByteArray())
        return secret?.let { bytes -> SecretBytes.adopt(bytes) }
    }

    private suspend fun mlKemEncapsulate(algorithm: KemAlgorithm, recipient: PublicKey): Encapsulation {
        val (secret, encapsulated) = crypto.backend.encapsulate(algorithm, recipient)
        return Encapsulation(sharedSecret = SecretBytes.adopt(secret), encapsulated = ByteString(encapsulated))
    }
}
