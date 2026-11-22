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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.cms.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.cipher.BlockCiphers
import kotlinx.io.bytestring.ByteString

private const val BLOCK: Int = 16
private const val HEADER: Int = 4
private const val CHECK_BYTES: Int = 3
private const val BYTE_MASK: Int = 0xFF
private const val MAXIMUM_KEY: Int = 255

internal object PasswordWrap {
    private val PADDING_BLOCK: ByteString = ByteString(ByteArray(BLOCK) { BLOCK.toByte() })

    suspend fun wrap(crypto: Crypto, kek: SecretBytes, iv: ByteString, key: SecretBytes): ByteString {
        require(key.size in CHECK_BYTES..MAXIMUM_KEY) { "The password wrap protects keys of 3 to 255 bytes" }
        val size = maxOf(a = 2 * BLOCK, b = (HEADER + key.size + BLOCK - 1) / BLOCK * BLOCK)
        val formatted = ByteArray(size)
        crypto.environment.random.fill(formatted)
        key.reveal { bytes ->
            formatted[0] = bytes.size.toByte()
            for (index in 0 until CHECK_BYTES) {
                formatted[1 + index] = (bytes[index].toInt() xor BYTE_MASK).toByte()
            }
            bytes.copyInto(destination = formatted, destinationOffset = HEADER)
        }
        val inner = encrypt(crypto = crypto, kek = kek, iv = iv, data = ByteString(formatted))
        formatted.fill(0)
        return encrypt(crypto = crypto, kek = kek, iv = lastBlock(inner), data = inner)
    }

    suspend fun unwrap(crypto: Crypto, kek: SecretBytes, iv: ByteString, wrapped: ByteString): SecretBytes? {
        val isShaped = wrapped.size >= 2 * BLOCK && wrapped.size % BLOCK == 0
        return wrapped.takeIf { isShaped }?.let { shaped ->
            unwrapShaped(
                crypto = crypto,
                kek = kek,
                iv = iv,
                wrapped = shaped,
            )
        }
    }

    private suspend fun unwrapShaped(
        crypto: Crypto,
        kek: SecretBytes,
        iv: ByteString,
        wrapped: ByteString,
    ): SecretBytes? {
        val size = wrapped.size
        val last = wrapped.substring(startIndex = size - BLOCK, endIndex = size)
        val previous = wrapped.substring(startIndex = size - 2 * BLOCK, endIndex = size - BLOCK)
        val tail = decrypt(crypto = crypto, kek = kek, iv = previous, data = last)
        val head = decrypt(
            crypto = crypto,
            kek = kek,
            iv = tail,
            data = wrapped.substring(startIndex = 0, endIndex = size - BLOCK),
        )
        val plain = decrypt(crypto = crypto, kek = kek, iv = iv, data = concat(listOf(head, tail))).toByteArray()
        val length = plain[0].toInt() and BYTE_MASK
        val check = (0 until CHECK_BYTES).fold(0) { found, index ->
            val difference = (plain[1 + index].toInt() xor plain[HEADER + index].toInt()) and BYTE_MASK
            found or (difference xor BYTE_MASK)
        }
        val isLength = length >= CHECK_BYTES && HEADER + length <= plain.size
        val isValid = check == 0 && isLength
        val key = plain.copyOfRange(fromIndex = HEADER, toIndex = HEADER + length.coerceAtMost(plain.size - HEADER))
        plain.fill(0)
        return SecretBytes.adopt(key).takeIf { isValid }
    }

    private suspend fun encrypt(crypto: Crypto, kek: SecretBytes, iv: ByteString, data: ByteString): ByteString {
        val padded = BlockCiphers.aesCbcEncrypt(crypto = crypto, key = kek, iv = iv, plaintext = data)
        return padded.substring(startIndex = 0, endIndex = data.size)
    }

    private suspend fun decrypt(crypto: Crypto, kek: SecretBytes, iv: ByteString, data: ByteString): ByteString {
        val closing = BlockCiphers.aesCbcEncrypt(
            crypto = crypto,
            key = kek,
            iv = lastBlock(data),
            plaintext = PADDING_BLOCK,
        )
        val extended = concat(listOf(data, closing.substring(startIndex = 0, endIndex = BLOCK)))
        val plain = BlockCiphers.aesCbcDecrypt(crypto = crypto, key = kek, iv = iv, ciphertext = extended)
        return checkNotNull(plain) { "AES-CBC refused a padding it made itself" }
    }

    private fun lastBlock(data: ByteString): ByteString = data.substring(
        startIndex = data.size - BLOCK,
        endIndex = data.size,
    )
}
