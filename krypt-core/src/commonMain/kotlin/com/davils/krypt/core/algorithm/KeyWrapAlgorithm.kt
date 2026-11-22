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

package com.davils.krypt.core.algorithm

/**
 * A key wrap, which encrypts a key with a key encryption key.
 *
 * @property algorithmName the canonical name of the algorithm.
 * @property securityBits the security strength in bits.
 * @property keyBytes the length of the key encryption key in bytes.
 * @property isLegacy whether the algorithm is broken or weak and exists only to read old data.
 * @property isFipsApproved whether FIPS 140-3 approves the algorithm.
 * @property isPostQuantum whether the algorithm resists a quantum computer.
 * @since 1.0.0
 */
public enum class KeyWrapAlgorithm(
    override val algorithmName: String,
    override val securityBits: Int,
    public val keyBytes: Int,
    override val isLegacy: Boolean = false,
    override val isFipsApproved: Boolean = true,
    override val isPostQuantum: Boolean = false,
) : Algorithm {
    /**
     * AES-128 key wrap of RFC 3394.
     *
     * @since 1.0.0
     */
    Aes128Kw(
        algorithmName = "AES-128-KW",
        securityBits = 128,
        keyBytes = 16,
    ),

    /**
     * AES-256 key wrap of RFC 3394, the default key wrap.
     *
     * @since 1.0.0
     */
    Aes256Kw(
        algorithmName = "AES-256-KW",
        securityBits = 256,
        keyBytes = 32,
    ),

    /**
     * AES-192 key wrap of RFC 3394, for formats such as COSE and JOSE that name it; WebCrypto of a browser may lack
     * it, which the capabilities tell.
     *
     * @since 1.0.0
     */
    Aes192Kw(
        algorithmName = "AES-192-KW",
        securityBits = 192,
        keyBytes = 24,
    ),
}
