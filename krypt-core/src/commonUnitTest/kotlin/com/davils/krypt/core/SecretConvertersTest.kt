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

import com.davils.kore.core.Limits
import com.davils.kore.core.arguments.conversion.ConversionException
import com.davils.kore.core.arguments.conversion.Converters
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain

private const val PASSWORD: String = "correct horse battery staple"

class SecretConvertersTest : FunSpec({
    context("the secret converter") {
        test("reads a secret that shows nothing of itself") {
            val secret = Converters.secretText.convert(PASSWORD)

            secret shouldBe SecretText.of(PASSWORD)
            secret.toString() shouldNotContain PASSWORD
            Converters.secretText.typeName shouldBe "secret"
        }

        test("refuses an empty and an overlong text without repeating it") {
            val overlong = "x".repeat(Limits.MAX_ARGUMENT_LENGTH + 1)

            listOf("", overlong).forEach { text ->
                val failure = shouldThrow<ConversionException> { Converters.secretText.convert(text) }
                failure.message shouldBe "is not a secret, expected 1 to 65536 characters"
            }
        }

        test("reads a secret at its longest") {
            val longest = "y".repeat(Limits.MAX_ARGUMENT_LENGTH)

            Converters.secretText.convert(longest) shouldBe SecretText.of(longest)
        }
    }
})
