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

package com.davils.krypt.jose.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.ConstantTime
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.jose.jwe.JweEncryption
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.cipher.BlockCiphers
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

private const val BYTE_BITS: Long = 8L
private const val LENGTH_BYTES: Int = 8
private const val BYTE_MASK: Long = 0xFF

internal class ContentCipher(private val crypto: Crypto) {
    suspend fun encrypt(
        encryption: JweEncryption,
        cek: SecretBytes,
        iv: ByteString,
        plaintext: ByteString,
        aad: ByteString,
    ): Pair<ByteString, ByteString> {
        val aead = encryption.aead ?: return cbcEncrypt(
            encryption = encryption,
            cek = cek,
            iv = iv,
            plaintext = plaintext,
            aad = aad,
        )
        val key = SecretKey.of(cek)
        val sealed = crypto.aead.encrypt(
            key = key,
            nonce = iv,
            plaintext = plaintext,
            associatedData = aad,
            algorithm = aead,
        )
        key.destroy()
        val bytes = sealed.toByteArray()
        val cut = bytes.size - aead.tagBytes
        return ByteString(data = bytes, startIndex = 0, endIndex = cut) to
            ByteString(data = bytes, startIndex = cut, endIndex = bytes.size)
    }

    suspend fun decrypt(
        encryption: JweEncryption,
        cek: SecretBytes,
        iv: ByteString,
        ciphertext: ByteString,
        tag: ByteString,
        aad: ByteString,
    ): ByteString? {
        val aead = encryption.aead ?: return cbcDecrypt(
            encryption = encryption,
            cek = cek,
            iv = iv,
            ciphertext = ciphertext,
            tag = tag,
            aad = aad,
        )
        val sealed = ciphertext.toByteArray() + tag.toByteArray()
        return gcmDecrypt(aead = aead, cek = cek, iv = iv, sealed = sealed, aad = aad)
    }

    private suspend fun gcmDecrypt(
        aead: AeadAlgorithm,
        cek: SecretBytes,
        iv: ByteString,
        sealed: ByteArray,
        aad: ByteString,
    ): ByteString? {
        val key = SecretKey.of(cek)
        val opened = crypto.aead.decrypt(
            key = key,
            nonce = iv,
            ciphertext = ByteString(sealed),
            associatedData = aad,
            algorithm = aead,
        )
        key.destroy()
        return opened
    }

    private suspend fun cbcEncrypt(
        encryption: JweEncryption,
        cek: SecretBytes,
        iv: ByteString,
        plaintext: ByteString,
        aad: ByteString,
    ): Pair<ByteString, ByteString> {
        val ciphertext = encryptionKeyOf(cek).use { encryptionKey ->
            BlockCiphers.aesCbcEncrypt(crypto = crypto, key = encryptionKey, iv = iv, plaintext = plaintext)
        }
        val tag = tagOf(encryption = encryption, cek = cek, iv = iv, ciphertext = ciphertext, aad = aad)
        return ciphertext to tag
    }

    private suspend fun cbcDecrypt(
        encryption: JweEncryption,
        cek: SecretBytes,
        iv: ByteString,
        ciphertext: ByteString,
        tag: ByteString,
        aad: ByteString,
    ): ByteString? {
        val expected = tagOf(encryption = encryption, cek = cek, iv = iv, ciphertext = ciphertext, aad = aad)
        val isAuthentic = ConstantTime.equals(first = expected, second = tag)
        if (!isAuthentic) return null
        return encryptionKeyOf(cek).use { encryptionKey ->
            BlockCiphers.aesCbcDecrypt(crypto = crypto, key = encryptionKey, iv = iv, ciphertext = ciphertext)
        }
    }

    private suspend fun tagOf(
        encryption: JweEncryption,
        cek: SecretBytes,
        iv: ByteString,
        ciphertext: ByteString,
        aad: ByteString,
    ): ByteString {
        val mac = invariant(encryption.mac)
        val bits = aad.size * BYTE_BITS
        val length = ByteArray(LENGTH_BYTES) { index ->
            (bits shr (LENGTH_BYTES - 1 - index) * Byte.SIZE_BITS and BYTE_MASK).toByte()
        }
        val input = aad.toByteArray() + iv.toByteArray() + ciphertext.toByteArray() + length
        val key = slice(secret = cek, from = 0, to = cek.size / 2).use { macKey -> SecretKey.of(macKey) }
        val full = crypto.macs.mac(key = key, data = ByteString(input), algorithm = mac)
        key.destroy()
        return ByteString(data = full.toByteArray(), startIndex = 0, endIndex = encryption.tagBytes)
    }

    private fun encryptionKeyOf(cek: SecretBytes): SecretBytes = slice(secret = cek, from = cek.size / 2, to = cek.size)

    private fun slice(secret: SecretBytes, from: Int, to: Int): SecretBytes =
        secret.reveal { bytes -> SecretBytes.adopt(bytes.copyOfRange(fromIndex = from, toIndex = to)) }
}
