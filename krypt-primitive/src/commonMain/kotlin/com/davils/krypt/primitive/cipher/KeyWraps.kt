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

package com.davils.krypt.primitive.cipher

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

private const val BYTE_BITS: Int = 8
private const val BLOCK: Int = 8
private const val MINIMUM_KEY: Int = 16

/**
 * The AES key wrap of RFC 3394, which encrypts a key with a key encryption key, deterministically and authenticated.
 *
 * @since 1.0.0
 */
public class KeyWraps internal constructor(private val crypto: Crypto) {
    /**
     * Wraps [key] under [kek].
     *
     * @param kek the key encryption key, of the length [algorithm] demands.
     * @param key the key to wrap, a multiple of 8 bytes and at least 16.
     * @param algorithm the key wrap; [KeyWrapAlgorithm.Aes256Kw] by default.
     * @return the wrapped key, 8 bytes longer than [key].
     * @throws IllegalArgumentException if a key has the wrong length.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm].
     * @since 1.0.0
     */
    public suspend fun wrap(
        kek: SecretKey,
        key: SecretBytes,
        algorithm: KeyWrapAlgorithm = KeyWrapAlgorithm.Aes256Kw,
    ): ByteString {
        require(
            kek.bits == algorithm.keyBytes * BYTE_BITS,
        ) { "${algorithm.algorithmName} needs a key of ${algorithm.keyBytes} bytes" }
        require(
            key.size >= MINIMUM_KEY && key.size % BLOCK == 0,
        ) { "A wrapped key has a multiple of 8 bytes, at least 16" }
        crypto.permit(algorithm, AlgorithmUse.Protect)
        return key.reveal { bytes -> ByteString(crypto.backend.wrap(algorithm, kek, bytes)) }
    }

    /**
     * Unwraps [wrapped] under [kek].
     *
     * @param kek the key encryption key.
     * @param wrapped the wrapped key.
     * @param algorithm the key wrap; [KeyWrapAlgorithm.Aes256Kw] by default.
     * @return the key, or null if [wrapped] is not authentic under [kek].
     * @throws IllegalArgumentException if [kek] has the wrong length.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm] for verification.
     * @since 1.0.0
     */
    public suspend fun unwrap(
        kek: SecretKey,
        wrapped: ByteString,
        algorithm: KeyWrapAlgorithm = KeyWrapAlgorithm.Aes256Kw,
    ): SecretBytes? {
        require(
            kek.bits == algorithm.keyBytes * BYTE_BITS,
        ) { "${algorithm.algorithmName} needs a key of ${algorithm.keyBytes} bytes" }
        crypto.permit(algorithm, AlgorithmUse.Verify)
        val isShaped = wrapped.size >= MINIMUM_KEY + BLOCK && wrapped.size % BLOCK == 0
        val bytes = wrapped.toByteArray().takeIf { isShaped } ?: return null
        return crypto.backend.unwrap(algorithm, kek, bytes)?.let { key -> SecretBytes.adopt(key) }
    }
}
