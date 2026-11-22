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

package com.davils.krypt.primitive.internal

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.primitive.key.SecretKey

internal interface SymmetricEngine {
    suspend fun digest(algorithm: DigestAlgorithm, data: ByteArray): ByteArray

    fun incrementalDigest(algorithm: DigestAlgorithm): IncrementalDigest?

    suspend fun mac(algorithm: MacAlgorithm, key: SecretKey, data: ByteArray): ByteArray

    suspend fun seal(
        algorithm: AeadAlgorithm,
        key: SecretKey,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray

    suspend fun open(
        algorithm: AeadAlgorithm,
        key: SecretKey,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray?

    suspend fun aesCbcEncrypt(key: SecretBytes, iv: ByteArray, data: ByteArray): ByteArray

    suspend fun aesCbcDecrypt(key: SecretBytes, iv: ByteArray, data: ByteArray): ByteArray?

    suspend fun wrap(algorithm: KeyWrapAlgorithm, kek: SecretKey, key: ByteArray): ByteArray

    suspend fun unwrap(algorithm: KeyWrapAlgorithm, kek: SecretKey, wrapped: ByteArray): ByteArray?

    suspend fun pbkdf2(
        digest: DigestAlgorithm,
        password: SecretText,
        salt: ByteArray,
        iterations: Int,
        length: Int,
    ): ByteArray
}
