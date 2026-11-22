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

package com.davils.krypt.jose.internal

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

private const val INT_BYTES: Int = 4
private const val BYTE_MASK: Int = 0xFF

internal object ConcatKdf {
    suspend fun derive(
        crypto: Crypto,
        secret: SecretBytes,
        algorithmId: String,
        partyU: ByteString,
        partyV: ByteString,
        bits: Int,
    ): SecretBytes {
        val other = prefixed(algorithmId.encodeToByteArray()) +
            prefixed(partyU.toByteArray()) +
            prefixed(partyV.toByteArray()) +
            int32(bits)
        val length = bits / Byte.SIZE_BITS
        val hashBytes = DigestAlgorithm.Sha256.outputBytes
        val rounds = (length + hashBytes - 1) / hashBytes
        val output = ByteArray(rounds * hashBytes)
        for (round in 1..rounds) {
            val digest = secret.reveal { z ->
                val input = int32(round) + z + other
                val hashed = crypto.digests.digest(data = ByteString(input), algorithm = DigestAlgorithm.Sha256)
                input.fill(0)
                hashed
            }
            digest.copyInto(destination = output, destinationOffset = (round - 1) * hashBytes)
        }
        val derived = output.copyOf(length)
        output.fill(0)
        return SecretBytes.adopt(derived)
    }

    private fun prefixed(bytes: ByteArray): ByteArray = int32(bytes.size) + bytes

    private fun int32(value: Int): ByteArray = ByteArray(INT_BYTES) { index ->
        (value shr (INT_BYTES - 1 - index) * Byte.SIZE_BITS and BYTE_MASK).toByte()
    }
}
