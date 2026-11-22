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

package com.davils.krypt.primitive.hash

import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

/**
 * Message digests: SHA-2, SHA-3 on the JVM, and SHA-1 and MD5 behind the legacy opt-in.
 *
 * @since 1.0.0
 */
public class Digests internal constructor(private val crypto: Crypto) {
    /**
     * Hashes [data].
     *
     * @param data the input, which must fit in memory; see [digester] for input in pieces.
     * @param algorithm the digest; [DigestAlgorithm.Sha256] by default.
     * @param use what the digest is for; checking a stored digest may use what the policy only verifies.
     * @return the digest.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm] for [use].
     * @throws com.davils.krypt.primitive.UnsupportedAlgorithmException if the platform lacks [algorithm].
     * @since 1.0.0
     */
    public suspend fun digest(
        data: ByteString,
        algorithm: DigestAlgorithm = DigestAlgorithm.Sha256,
        use: AlgorithmUse = AlgorithmUse.Protect,
    ): ByteString {
        crypto.permit(algorithm, use)
        return ByteString(crypto.backend.digest(algorithm, data.toByteArray()))
    }

    /**
     * Returns a digester for input in pieces, or null on a platform without incremental hashing, such as WebCrypto.
     *
     * @param algorithm the digest; [DigestAlgorithm.Sha256] by default.
     * @param use what the digest is for.
     * @return the digester, or null if the platform hashes only whole inputs.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm] for [use].
     * @throws com.davils.krypt.primitive.UnsupportedAlgorithmException if the platform lacks [algorithm].
     * @since 1.0.0
     */
    public fun digester(
        algorithm: DigestAlgorithm = DigestAlgorithm.Sha256,
        use: AlgorithmUse = AlgorithmUse.Protect,
    ): Digester? {
        crypto.permit(algorithm, use)
        return crypto.backend.incrementalDigest(algorithm)?.let { digest -> Digester(algorithm, digest) }
    }
}
