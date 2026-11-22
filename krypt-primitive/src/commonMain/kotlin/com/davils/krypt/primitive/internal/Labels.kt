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
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val BYTE_BITS: Int = 8
private const val BYTE_MASK: Int = 0xFF

internal class Labels(private val crypto: Crypto, private val suiteId: ByteString, private val kdf: KdfAlgorithm) {
    suspend fun extract(salt: ByteString, label: String, inputKey: ByteString): SecretBytes {
        val labeled = VERSION.toByteArray() + suiteId.toByteArray() + label.encodeToByteArray() + inputKey.toByteArray()
        val ikm = SecretBytes.adopt(labeled)
        return ikm.use { owned -> crypto.derivations.extract(salt = salt, inputKey = owned, algorithm = kdf) }
    }

    suspend fun expand(prk: SecretBytes, label: String, info: ByteString, length: Int): SecretBytes {
        val labeled = twoBytes(length) +
            VERSION.toByteArray() +
            suiteId.toByteArray() +
            label.encodeToByteArray() +
            info.toByteArray()
        return crypto.derivations.expand(
            pseudorandomKey = prk,
            info = ByteString(labeled),
            length = length,
            algorithm = kdf,
        )
    }

    companion object {
        val VERSION: ByteString = "HPKE-v1".encodeToByteString()

        fun twoBytes(value: Int): ByteArray = byteArrayOf(
            (value shr BYTE_BITS and BYTE_MASK).toByte(),
            (value and BYTE_MASK).toByte(),
        )
    }
}
