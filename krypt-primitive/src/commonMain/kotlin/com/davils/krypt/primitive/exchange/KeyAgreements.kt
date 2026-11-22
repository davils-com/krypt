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
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.CryptoException
import com.davils.krypt.primitive.internal.platformRefusal
import com.davils.krypt.primitive.internal.requireSupported
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey

/**
 * Key agreement: X25519, X448 on the JVM, and ECDH on the NIST curves.
 *
 * The raw shared secret is not a key: derive keys from it with HKDF, or use [Kems] or [Hpke], which do.
 *
 * @since 1.0.0
 */
public class KeyAgreements internal constructor(private val crypto: Crypto) {
    /**
     * Agrees on a shared secret between [privateKey] and [publicKey].
     *
     * @param privateKey the own private key.
     * @param publicKey the public key of the peer, of the same family and curve.
     * @return the raw shared secret: the x-coordinate for ECDH, the u-coordinate for X25519 and X448.
     * @throws IllegalArgumentException if the keys do not agree or do not belong to a key agreement family.
     * @throws IllegalStateException if [privateKey] was destroyed.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids the agreement or the keys.
     * @throws com.davils.krypt.primitive.UnsupportedAlgorithmException if the platform lacks the agreement.
     * @throws CryptoException if the platform refuses one of the keys, such as a peer key of small order or a point
     *   off the curve; the exception carries nothing of the failure of the platform.
     * @since 1.0.0
     */
    public suspend fun agree(privateKey: PrivateKey, publicKey: PublicKey): SecretBytes =
        agreeOrNull(privateKey = privateKey, publicKey = publicKey) ?: throw platformRefusal()

    internal suspend fun agreeOrNull(privateKey: PrivateKey, publicKey: PublicKey): SecretBytes? {
        require(privateKey.family == publicKey.family && privateKey.curve == publicKey.curve) {
            "Both keys of an agreement have the same family and curve"
        }
        val algorithm = algorithmFor(privateKey.family, privateKey.curve)
        crypto.permit(algorithm, AlgorithmUse.Protect)
        crypto.permitKey(publicKey, AlgorithmUse.Protect)
        crypto.requireSupported(algorithm)
        val secret = crypto.backend.agree(algorithm, privateKey, publicKey)
        return secret?.let { bytes -> SecretBytes.adopt(bytes) }
    }

    /**
     * Returns the agreement for keys of [family] on [curve].
     *
     * @param family the family of the keys.
     * @param curve the curve of elliptic curve keys.
     * @return the agreement.
     * @throws IllegalArgumentException if keys of [family] do not agree.
     * @since 1.0.0
     */
    public fun algorithmFor(family: KeyFamily, curve: EllipticCurve?): KeyAgreementAlgorithm {
        val algorithm = KeyAgreementAlgorithm.entries.firstOrNull { candidate ->
            candidate.family == family &&
                candidate.curve == curve
        }
        return requireNotNull(algorithm) { "A $family key does not agree on a secret" }
    }
}
