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
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.primitive.Crypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val KEY: String = "2b7e151628aed2a6abf7158809cf4f3c"
private const val IV: String = "000102030405060708090a0b0c0d0e0f"
private const val PLAINTEXT: String = "6bc1bee22e409f96e93d7e117393172a"
private const val FIRST_BLOCK: String = "7649abac8119b246cee98e9b12e9197d"
private const val BLOCK: Int = 16

private fun hex(text: String): ByteString = checkNotNull(Hex.decode(text).getOrNull())

class BlockCiphersTest : FunSpec({
    val crypto = Crypto()
    val key = SecretBytes.copyOf(hex(KEY))

    test("AES-CBC matches SP 800-38A and round trips with padding") {
        val iv = hex(IV)
        val encrypted = BlockCiphers.aesCbcEncrypt(crypto = crypto, key = key, iv = iv, plaintext = hex(PLAINTEXT))
        encrypted.size shouldBe BLOCK * 2
        encrypted.substring(startIndex = 0, endIndex = BLOCK) shouldBe hex(FIRST_BLOCK)
        val decrypted = BlockCiphers.aesCbcDecrypt(crypto = crypto, key = key, iv = hex(IV), ciphertext = encrypted)
        decrypted shouldBe hex(PLAINTEXT)
    }

    test("wrong lengths and padding are refused") {
        val iv = hex(IV)
        BlockCiphers.aesCbcDecrypt(crypto = crypto, key = key, iv = iv, ciphertext = ByteString()) shouldBe null
        BlockCiphers.aesCbcDecrypt(crypto = crypto, key = key, iv = iv, ciphertext = hex(PLAINTEXT)) shouldBe null
        BlockCiphers.aesCbcDecrypt(crypto = crypto, key = key, iv = iv, ciphertext = ByteString(1)) shouldBe null
        shouldThrow<IllegalArgumentException> {
            val short = SecretBytes.copyOf(ByteArray(1))
            BlockCiphers.aesCbcEncrypt(crypto = crypto, key = short, iv = hex(IV), plaintext = hex(IV))
        }
        shouldThrow<IllegalArgumentException> {
            BlockCiphers.aesCbcEncrypt(crypto = crypto, key = key, iv = ByteString(1), plaintext = hex(IV))
        }
    }
})
