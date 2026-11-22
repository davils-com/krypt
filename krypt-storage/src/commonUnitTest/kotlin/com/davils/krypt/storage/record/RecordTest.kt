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

package com.davils.krypt.storage.record

import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.storage.fixture.keysets
import com.davils.krypt.storage.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain

private const val TABLE: String = "customers"
private const val COLUMN: String = "iban"
private const val VALUE: String = "DE89 3704 0044 0532 0130 00"
private const val EMAIL: String = "Ada@Example.org"
private const val BELL: String = "\u0007"
private const val LONG_TEXT: Int = 300
private const val SHORT_INDEX: Int = 23

class RecordTest : FunSpec({
    test("a field is bound to its table, column and row") {
        val cipher = RecordCipher(keysets.aead(keysets.generate(KeyPurpose.Aead())))
        val context = RecordContext(table = TABLE, column = COLUMN, row = "1")
        val ciphertext = cipher.encrypt(utf8(VALUE), context)
        cipher.decrypt(ciphertext, context) shouldBe utf8(VALUE)
        cipher.decrypt(ciphertext, RecordContext(table = TABLE, column = COLUMN, row = "2")) shouldBe null
        cipher.encrypt(utf8(VALUE), context) shouldNotBe ciphertext
        val text = cipher.encryptText(VALUE, context)
        cipher.decryptText(text, context) shouldBe VALUE
        cipher.decryptText("!!", context) shouldBe null
        cipher.decryptText(text, RecordContext(table = TABLE, column = "bic", row = "1")) shouldBe null
        cipher.toString() shouldContain "RecordCipher"
    }

    test("a record context checks and hides its parts") {
        val context = RecordContext(table = TABLE, column = COLUMN, row = BELL)
        context.toString() shouldNotContain BELL
        context shouldBe RecordContext(table = TABLE, column = COLUMN, row = BELL)
        context shouldNotBe RecordContext(table = TABLE, column = COLUMN, row = "1")
        context shouldNotBe Any()
        context.hashCode() shouldBe listOf(TABLE, COLUMN, BELL).hashCode()
        shouldThrow<IllegalArgumentException> { RecordContext(table = "", column = COLUMN, row = "1") }
        shouldThrow<IllegalArgumentException> {
            RecordContext(
                table = TABLE,
                column = COLUMN,
                row = "x".repeat(LONG_TEXT),
            )
        }
    }

    test("a blind index finds equal values in one column only") {
        val keyset = keysets.generate(KeyPurpose.Mac())
        val emails = BlindIndex(mac = keysets.mac(keyset), column = "email", normalize = { value -> value.lowercase() })
        emails.of(EMAIL) shouldBe emails.of(EMAIL.lowercase())
        emails.of(EMAIL) shouldNotBe emails.of("grace@example.org")
        val names = BlindIndex(mac = keysets.mac(keyset), column = "name", size = 8)
        names.of(EMAIL) shouldNotBe emails.of(EMAIL)
        names.of(EMAIL).length shouldBe SHORT_INDEX
        val rotated = BlindIndex(
            mac = keysets.mac(keysets.rotate(keyset)),
            column = "email",
            normalize = { value -> value.lowercase() },
        )
        rotated.candidates(EMAIL).last() shouldBe emails.of(EMAIL)
        rotated.candidates(EMAIL).size shouldBe 2
        emails.toString() shouldBe "BlindIndex(column=5 characters, size=16)"
        shouldThrow<IllegalArgumentException> { BlindIndex(mac = keysets.mac(keyset), column = "x", size = 4) }
        shouldThrow<IllegalArgumentException> { BlindIndex(mac = keysets.mac(keyset), column = "x", size = 33) }
        shouldThrow<IllegalArgumentException> { BlindIndex(mac = keysets.mac(keyset), column = "") }
    }
})
