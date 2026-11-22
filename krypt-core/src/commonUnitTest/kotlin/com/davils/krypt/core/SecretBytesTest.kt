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

package com.davils.krypt.core

import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.core.fixture.bytes
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString

private const val SECRET_SIZE: Int = 4
private const val FOUR_BYTES: String = "01020304"
private const val SEVENS: String = "0707"

class SecretBytesTest : FunSpec({
    test("a secret copies what it is given and lends its bytes") {
        val source = bytes(FOUR_BYTES)
        val secret = SecretBytes.copyOf(source)
        source.fill(0)
        secret.reveal { revealed -> Hex.encode(revealed) } shouldBe FOUR_BYTES
        secret.size shouldBe SECRET_SIZE
        SecretBytes.copyOf(ByteString(bytes(SEVENS))).reveal { revealed -> revealed.size } shouldBe 2
    }

    test("destroying wipes the adopted array and refuses every later read") {
        val array = bytes(SEVENS)
        val secret = SecretBytes.adopt(array)
        secret.destroy()
        secret.destroy()
        Hex.encode(array) shouldBe "0000"
        secret.isDestroyed shouldBe true
        secret.size shouldBe 2
        shouldThrow<IllegalStateException> { secret.reveal { revealed -> revealed } }
        shouldThrow<IllegalStateException> { secret.copy() }
        shouldThrow<IllegalStateException> { secret.prefix(1) }
    }

    test("use destroys the secret afterwards, also after a failure") {
        val secret = SecretBytes.copyOf(bytes(SEVENS))
        secret.use { open -> open.isDestroyed } shouldBe false
        secret.isDestroyed shouldBe true
        val failing = SecretBytes.copyOf(bytes(SEVENS))
        shouldThrow<IllegalStateException> { failing.use { _ -> error("the block failed") } }
        failing.isDestroyed shouldBe true
    }

    test("copies and prefixes are independent secrets") {
        val secret = SecretBytes.copyOf(bytes(FOUR_BYTES))
        val copy = secret.copy()
        val prefix = secret.prefix(2)
        secret.destroy()
        copy.reveal { revealed -> Hex.encode(revealed) } shouldBe FOUR_BYTES
        prefix.reveal { revealed -> Hex.encode(revealed) } shouldBe "0102"
        shouldThrow<IllegalArgumentException> { copy.prefix(SECRET_SIZE + 1) }
        shouldThrow<IllegalArgumentException> { copy.prefix(-1) }
    }

    test("equality compares the bytes, hashing and text reveal nothing") {
        val first = SecretBytes.copyOf(bytes(SEVENS))
        val second = SecretBytes.copyOf(bytes(SEVENS))
        (first == second) shouldBe true
        (first == first) shouldBe true
        first shouldNotBe SecretBytes.copyOf(bytes("0708"))
        first.equals(SEVENS) shouldBe false
        first.hashCode() shouldBe 2
        first.toString() shouldBe "SecretBytes(size=2, bytes=****, destroyed=false)"
        second.destroy()
        (first == second) shouldBe false
        (second == first) shouldBe false
    }

    test("a random secret draws its bytes from the source") {
        val secret = SecretBytes.random(size = 2, random = { target -> target.fill(1) })
        secret.reveal { revealed -> Hex.encode(revealed) } shouldBe "0101"
        shouldThrow<IllegalArgumentException> { SecretBytes.random(size = 0, random = RandomSource.Secure) }
    }
})
