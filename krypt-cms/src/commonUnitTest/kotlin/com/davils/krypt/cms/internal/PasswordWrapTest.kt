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
import com.davils.krypt.cms.fixture.crypto
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.primitive.cipher.BlockCiphers
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val BLOCK: Int = 16
private const val KEY_BYTES: Int = 32
private const val TOO_LONG: Int = 256
private const val CHECK: Int = 0xFF
private const val CHECK_BYTES: Int = 3
private const val KEY_FILL: Byte = 7

private val kek: SecretBytes = SecretBytes.copyOf(ByteArray(KEY_BYTES) { 3 })
private val iv: ByteString = ByteString(ByteArray(BLOCK) { 5 })

private suspend fun raw(iv: ByteString, data: ByteString): ByteString {
    val padded = BlockCiphers.aesCbcEncrypt(crypto = crypto, key = kek, iv = iv, plaintext = data)
    return padded.substring(startIndex = 0, endIndex = data.size)
}

private suspend fun wrapped(formatted: ByteArray): ByteString {
    val inner = raw(iv = iv, data = ByteString(formatted))
    return raw(iv = inner.substring(startIndex = inner.size - BLOCK, endIndex = inner.size), data = inner)
}

class PasswordWrapTest : FunSpec({
    test("the wrap round trips and refuses keys it cannot format") {
        val key = SecretBytes.copyOf(ByteArray(KEY_BYTES) { KEY_FILL })
        val wrapped = PasswordWrap.wrap(crypto = crypto, kek = kek, iv = iv, key = key)
        val unwrapped = PasswordWrap.unwrap(crypto = crypto, kek = kek, iv = iv, wrapped = wrapped)
        unwrapped?.reveal { bytes -> ByteString(bytes) } shouldBe ByteString(ByteArray(KEY_BYTES) { KEY_FILL })
        shouldThrow<IllegalArgumentException> {
            PasswordWrap.wrap(crypto = crypto, kek = kek, iv = iv, key = SecretBytes.copyOf(ByteArray(2)))
        }
        shouldThrow<IllegalArgumentException> {
            PasswordWrap.wrap(crypto = crypto, kek = kek, iv = iv, key = SecretBytes.copyOf(ByteArray(TOO_LONG)))
        }
    }

    test("a wrong length or check value is refused") {
        val short = ByteArray(2 * BLOCK)
        short[0] = 2
        val long = ByteArray(2 * BLOCK)
        long[0] = (2 * BLOCK).toByte()
        val unchecked = ByteArray(2 * BLOCK)
        unchecked[0] = BLOCK.toByte()
        val checked = ByteArray(2 * BLOCK)
        checked[0] = BLOCK.toByte()
        for (index in 1..CHECK_BYTES) checked[index] = CHECK.toByte()
        listOf(short, long, unchecked).forEach { formatted ->
            PasswordWrap.unwrap(crypto = crypto, kek = kek, iv = iv, wrapped = wrapped(formatted)) shouldBe null
        }
        PasswordWrap.unwrap(crypto = crypto, kek = kek, iv = iv, wrapped = wrapped(checked))?.size shouldBe BLOCK
    }
})
