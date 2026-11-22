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
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

private const val SECRET: String = "secret"
private const val LENGTH: Int = 5

private fun utf8Of(text: SecretText): String = text.utf8().reveal { bytes -> Hex.encode(bytes) }

private fun expectedOf(text: String): String = Hex.encode(text.encodeToByteArray())

class SecretTextTest : FunSpec({
    test("UTF-8 encodes one to four byte characters like the standard library") {
        val text = "aä€😀"
        val secret = SecretText.of(text)
        utf8Of(secret) shouldBe expectedOf(text)
        secret.length shouldBe LENGTH
    }

    test("a lone surrogate becomes the replacement character") {
        val secret = SecretText.copyOf(charArrayOf('a', '\uD800', 'b', '\uDC00'))
        utf8Of(secret) shouldBe expectedOf("a�b�")
        utf8Of(SecretText.copyOf(charArrayOf('\uD800'))) shouldBe expectedOf("�")
    }

    test("destroying wipes the adopted characters and refuses every later read") {
        val chars = charArrayOf('p', 'w')
        val secret = SecretText.adopt(chars)
        secret.reveal { value -> value.concatToString() } shouldBe "pw"
        secret.use { open -> open.isDestroyed } shouldBe false
        chars.concatToString() shouldBe "\u0000\u0000"
        secret.isDestroyed shouldBe true
        secret.destroy()
        shouldThrow<IllegalStateException> { secret.utf8() }
        shouldThrow<IllegalStateException> { secret.reveal { value -> value } }
    }

    test("equality compares the characters, hashing and text reveal nothing") {
        val first = SecretText.of(SECRET)
        val second = SecretText.of(SECRET)
        (first == second) shouldBe true
        (first == first) shouldBe true
        first shouldNotBe SecretText.of("secreT")
        first shouldNotBe SecretText.of("secrets")
        first.equals(SECRET) shouldBe false
        first.hashCode() shouldBe SECRET.length
        first.toString() shouldBe "SecretText(length=6, text=****, destroyed=false)"
        second.destroy()
        (first == second) shouldBe false
        (second == first) shouldBe false
    }
})
