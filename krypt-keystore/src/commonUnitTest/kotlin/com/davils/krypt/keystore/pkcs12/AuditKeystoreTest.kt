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

package com.davils.krypt.keystore.pkcs12

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.keystore.fixture.crypto
import com.davils.krypt.keystore.fixture.issue
import com.davils.krypt.keystore.fixture.password
import com.davils.krypt.keystore.internal.BagAttributes
import com.davils.krypt.keystore.internal.Pkcs12Writer
import com.davils.krypt.primitive.cipher.PasswordEncryption
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.TimeSource

private const val AUDIT_ITERATIONS: Int = 100_000
private const val MANY_CONTENTS: Int = 32
private const val SALT_BYTES: Int = 16
private const val KEY_BYTES: Int = 32
private const val ALLOWED_FACTOR: Long = 4L

private suspend fun storeWith(contents: Int): ByteString {
    val issued = issue("audit")
    val bag = Pkcs12Writer.certificateBag(issued.certificate.encoded, BagAttributes())
    val plaintext = Pkcs12Writer.safeContents(listOf(bag))
    val encrypted = (1..contents).map {
        val (algorithm, ciphertext) = SecretBytes.copyOf(plaintext).use { content ->
            PasswordEncryption.encrypt(
                crypto = crypto,
                plaintext = content,
                password = password(),
                iterations = AUDIT_ITERATIONS,
            )
        }
        Pkcs12Writer.encrypted(algorithm = algorithm, ciphertext = ciphertext)
    }
    val authenticated = Pkcs12Writer.authenticatedSafe(encrypted)
    val salt = ByteString(ByteArray(SALT_BYTES) { 1 })
    val derived = crypto.derivations.pbkdf2(
        password = password(),
        salt = salt,
        iterations = AUDIT_ITERATIONS,
        length = KEY_BYTES,
    )
    val key = derived.use { bytes -> SecretKey.of(bytes) }
    val tag = crypto.macs.mac(key = key, data = authenticated)
    return Pkcs12Writer.pfx(authenticated = authenticated, salt = salt, iterations = AUDIT_ITERATIONS, tag = tag)
}

private suspend fun millisToDecode(store: ByteString): Long {
    val start = TimeSource.Monotonic.markNow()
    val decoded = Pkcs12(crypto).decode(store, password())
    decoded.getOrNull() shouldNotBe null
    return start.elapsedNow().inWholeMilliseconds
}

class AuditKeystoreTest : FunSpec({
    test("the password work of one decode is bounded, not multiplied by the number of encrypted contents") {
        val one = storeWith(1)
        val many = storeWith(MANY_CONTENTS)
        millisToDecode(one)
        val single = millisToDecode(one)
        val multiplied = millisToDecode(many)
        println("audit: 1 content $single ms, $MANY_CONTENTS contents $multiplied ms at $AUDIT_ITERATIONS iterations")
        multiplied shouldBeLessThan ALLOWED_FACTOR * maxOf(single, 1L)
    }
})
