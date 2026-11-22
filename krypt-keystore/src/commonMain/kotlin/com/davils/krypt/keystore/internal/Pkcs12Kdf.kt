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

package com.davils.krypt.keystore.internal

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.unsafe.UnsafeByteStringApi
import kotlinx.io.bytestring.unsafe.UnsafeByteStringOperations

private const val MAC_ID: Byte = 3
private const val BYTE_BITS: Int = 8

@OptIn(UnsafeByteStringApi::class)
internal object Pkcs12Kdf {
    suspend fun macKey(
        crypto: Crypto,
        digest: DigestAlgorithm,
        password: SecretText,
        salt: ByteString,
        iterations: Int,
    ): SecretBytes {
        val block = digest.blockBytes
        val diversifier = ByteArray(block) { MAC_ID }
        val stretchedSalt = stretch(bytes = salt.toByteArray(), block = block)
        val passwordBytes = bmp(password)
        val stretchedPassword = stretch(bytes = passwordBytes, block = block)
        val input = diversifier + stretchedSalt + stretchedPassword
        passwordBytes.fill(0)
        stretchedPassword.fill(0)
        var current = try {
            crypto.digests.digest(
                data = UnsafeByteStringOperations.wrapUnsafe(input),
                algorithm = digest,
                use = AlgorithmUse.Verify,
            )
        } finally {
            input.fill(0)
        }
        repeat(iterations - 1) {
            val next = crypto.digests.digest(data = current, algorithm = digest, use = AlgorithmUse.Verify)
            wipe(current)
            current = next
        }
        return try {
            SecretBytes.copyOf(current)
        } finally {
            wipe(current)
        }
    }

    private fun wipe(bytes: ByteString) {
        UnsafeByteStringOperations.withByteArrayUnsafe(bytes) { array -> array.fill(0) }
    }

    private fun bmp(password: SecretText): ByteArray = password.reveal { chars ->
        ByteArray(chars.size * 2 + 2) { index ->
            val code = chars.getOrNull(index / 2)?.code ?: 0
            (code shr BYTE_BITS * (1 - index % 2)).toByte()
        }
    }

    private fun stretch(bytes: ByteArray, block: Int): ByteArray {
        val length = block * ((bytes.size + block - 1) / block)
        return ByteArray(length) { index -> bytes[index % bytes.size] }
    }
}
