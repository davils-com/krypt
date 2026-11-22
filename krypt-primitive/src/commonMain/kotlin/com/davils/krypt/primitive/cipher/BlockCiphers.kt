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

package com.davils.krypt.primitive.cipher

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

private const val IV_BYTES: Int = 16
private val KEY_SIZES: Set<Int> = setOf(16, 24, 32)

/**
 * AES in CBC mode with PKCS #7 padding, for formats that need it and authenticate it themselves, such as the
 * AES-CBC-HMAC content encryption of JOSE and the content encryption of CMS.
 *
 * CBC is no authenticated encryption: a caller that decrypts before it checked a MAC or a signature opens a padding
 * oracle. Use [Aeads] everywhere else. AES-192 is not available in every WebCrypto implementation.
 *
 * @since 1.0.0
 */
@DavilsInternal
public object BlockCiphers {
    /**
     * Encrypts [plaintext] under [key] and [iv].
     *
     * @param crypto the primitives.
     * @param key the AES key of 16, 24 or 32 bytes.
     * @param iv the initialisation vector of 16 bytes; it must be unpredictable.
     * @param plaintext the message.
     * @return the ciphertext with its padding.
     * @throws IllegalArgumentException if the key or the IV has the wrong length.
     * @since 1.0.0
     */
    public suspend fun aesCbcEncrypt(
        crypto: Crypto,
        key: SecretBytes,
        iv: ByteString,
        plaintext: ByteString,
    ): ByteString {
        check(key = key, iv = iv)
        val encrypted = crypto.backend.aesCbcEncrypt(key = key, iv = iv.toByteArray(), data = plaintext.toByteArray())
        return ByteString(encrypted)
    }

    /**
     * Decrypts what [aesCbcEncrypt] encrypted.
     *
     * @param crypto the primitives.
     * @param key the AES key of 16, 24 or 32 bytes.
     * @param iv the initialisation vector of 16 bytes.
     * @param ciphertext the ciphertext, possibly from an attacker; authenticate it before.
     * @return the plaintext, or null if the length or the padding is wrong.
     * @throws IllegalArgumentException if the key or the IV has the wrong length.
     * @since 1.0.0
     */
    public suspend fun aesCbcDecrypt(
        crypto: Crypto,
        key: SecretBytes,
        iv: ByteString,
        ciphertext: ByteString,
    ): ByteString? {
        check(key = key, iv = iv)
        val isBlocks = ciphertext.size > 0 && ciphertext.size % IV_BYTES == 0
        val decrypted = ciphertext.takeIf { isBlocks }?.let { bytes ->
            crypto.backend.aesCbcDecrypt(key = key, iv = iv.toByteArray(), data = bytes.toByteArray())
        }
        return decrypted?.let { plain -> ByteString(plain) }
    }

    private fun check(key: SecretBytes, iv: ByteString) {
        require(key.size in KEY_SIZES) { "AES needs a key of 16, 24 or 32 bytes" }
        require(iv.size == IV_BYTES) { "AES-CBC needs an IV of $IV_BYTES bytes" }
    }
}
