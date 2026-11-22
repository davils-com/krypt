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

import com.davils.krypt.core.ConstantTime
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.Verification
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

/**
 * Message authentication codes: HMAC with SHA-2.
 *
 * Verification compares the whole tag in constant time; a truncated tag is never accepted.
 *
 * @since 1.0.0
 */
public class Macs internal constructor(private val crypto: Crypto) {
    /**
     * Computes the tag of [data].
     *
     * @param key the key, at least 128 bits.
     * @param data the input.
     * @param algorithm the MAC; [MacAlgorithm.HmacSha256] by default.
     * @return the tag.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm].
     * @since 1.0.0
     */
    public suspend fun mac(
        key: SecretKey,
        data: ByteString,
        algorithm: MacAlgorithm = MacAlgorithm.HmacSha256,
    ): ByteString {
        crypto.permit(algorithm, AlgorithmUse.Protect)
        return ByteString(crypto.backend.mac(algorithm, key, data.toByteArray()))
    }

    /**
     * Checks [tag] against [data] in constant time.
     *
     * @param key the key.
     * @param data the input.
     * @param tag the tag to check.
     * @param algorithm the MAC; [MacAlgorithm.HmacSha256] by default.
     * @return whether the tag is valid.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm] for verification.
     * @since 1.0.0
     */
    public suspend fun verify(
        key: SecretKey,
        data: ByteString,
        tag: ByteString,
        algorithm: MacAlgorithm = MacAlgorithm.HmacSha256,
    ): Verification {
        crypto.permit(algorithm, AlgorithmUse.Verify)
        val expected = crypto.backend.mac(algorithm, key, data.toByteArray())
        return Verification.of(ConstantTime.equals(first = expected, second = tag.toByteArray()))
    }
}
