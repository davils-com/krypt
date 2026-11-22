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
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.keystore.KeystoreFailure
import com.davils.krypt.keystore.KeystoreLimits
import com.davils.krypt.keystore.fixture.ITERATIONS
import com.davils.krypt.keystore.fixture.crypto
import com.davils.krypt.keystore.fixture.der
import com.davils.krypt.keystore.fixture.identity
import com.davils.krypt.keystore.fixture.issue
import com.davils.krypt.keystore.fixture.password
import com.davils.krypt.keystore.internal.BagAttributes
import com.davils.krypt.keystore.internal.Pkcs12Oids
import com.davils.krypt.keystore.internal.Pkcs12Writer
import com.davils.krypt.primitive.cipher.PasswordEncryption
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val MANY_CONTENTS: Int = 32
private const val FEW_CONTENTS: Int = 3
private const val BUDGET_DERIVATIONS: Int = 10
private const val SALT_BYTES: Int = 16
private const val KEY_BYTES: Int = 32
private const val FIRST: String = "first"
private const val SECOND: String = "second"
private val PBES2: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.5.13")
private val BROKEN_PBES2: ByteString = der {
    sequence {
        objectIdentifier(PBES2)
        sequence { nullValue() }
    }
}

private suspend fun encryptedContent(): ByteString {
    val issued = issue("work")
    val bag = Pkcs12Writer.certificateBag(issued.certificate.encoded, BagAttributes())
    val plaintext = Pkcs12Writer.safeContents(listOf(bag))
    val (algorithm, ciphertext) = SecretBytes.copyOf(plaintext).use { content ->
        PasswordEncryption.encrypt(crypto = crypto, plaintext = content, password = password(), iterations = ITERATIONS)
    }
    return Pkcs12Writer.encrypted(algorithm = algorithm, ciphertext = ciphertext)
}

private suspend fun protected(contents: List<ByteString>): ByteString {
    val authenticated = Pkcs12Writer.authenticatedSafe(contents)
    val salt = ByteString(ByteArray(SALT_BYTES) { 1 })
    val derived = crypto.derivations.pbkdf2(
        password = password(),
        salt = salt,
        iterations = ITERATIONS,
        length = KEY_BYTES,
    )
    val key = derived.use { bytes -> SecretKey.of(bytes) }
    val tag = crypto.macs.mac(key = key, data = authenticated)
    return Pkcs12Writer.pfx(authenticated = authenticated, salt = salt, iterations = ITERATIONS, tag = tag)
}

private fun budgetOf(derivations: Int): Pkcs12 =
    Pkcs12(crypto, KeystoreLimits(maximumPasswordIterations = derivations * ITERATIONS))

class PasswordWorkTest : FunSpec({
    test("the password work of one file is bounded, not multiplied by its encrypted contents") {
        val content = encryptedContent()
        val few = protected(List(FEW_CONTENTS) { content })
        val many = protected(List(MANY_CONTENTS) { content })
        val bounded = budgetOf(BUDGET_DERIVATIONS)
        val fewRead = bounded.decode(few, password())
        fewRead.getOrNull() shouldNotBe null
        val manyRead = bounded.decode(many, password())
        manyRead.failureOrNull() shouldBe KeystoreFailure.Refused
        val unbounded = Pkcs12(crypto).decode(many, password())
        unbounded.getOrNull() shouldNotBe null
    }

    test("shrouded keys count against the password work") {
        val (first, _) = identity(FIRST)
        val (second, _) = identity(SECOND)
        val store = Pkcs12Store(keys = listOf(KeyEntry(first, alias = FIRST), KeyEntry(second, alias = SECOND)))
        val encoded = Pkcs12(crypto).encode(store, password(), ITERATIONS)
        val derivations = 1 + 1 + store.keys.size
        val enough = budgetOf(derivations).decode(encoded, password())
        enough.getOrNull()?.run { keys.size } shouldBe store.keys.size
        val short = budgetOf(derivations - 1).decode(encoded, password())
        short.failureOrNull() shouldBe KeystoreFailure.Refused
    }

    test("password parameters that cannot be read are malformed") {
        val content = Pkcs12Writer.encrypted(algorithm = BROKEN_PBES2, ciphertext = ByteString(0))
        val brokenContent = Pkcs12(crypto).decode(protected(listOf(content)), password())
        brokenContent.failureOrNull() shouldBe KeystoreFailure.Malformed
        val shrouded = der {
            sequence {
                raw(BROKEN_PBES2)
                octetString(ByteString(0))
            }
        }
        val bag = Pkcs12Writer.bag(type = Pkcs12Oids.SHROUDED_KEY_BAG, value = shrouded, attributes = BagAttributes())
        val plain = Pkcs12Writer.plain(Pkcs12Writer.safeContents(listOf(bag)))
        val brokenKey = Pkcs12(crypto).decode(protected(listOf(plain)), password())
        brokenKey.failureOrNull() shouldBe KeystoreFailure.Malformed
    }

    test("the password work has a hard ceiling") {
        val limits = KeystoreLimits(maximumPasswordIterations = ITERATIONS)
        limits shouldBe KeystoreLimits(maximumPasswordIterations = ITERATIONS)
        (limits == KeystoreLimits()) shouldBe false
        limits.toString() shouldContain "maximumPasswordIterations=$ITERATIONS"
        shouldThrow<IllegalArgumentException> { KeystoreLimits(maximumPasswordIterations = 0) }
        shouldThrow<IllegalArgumentException> {
            KeystoreLimits(maximumPasswordIterations = KeystoreLimits.HARD_MAXIMUM_PASSWORD_ITERATIONS + 1)
        }
    }
})
