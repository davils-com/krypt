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

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import kotlinx.io.bytestring.ByteString

private const val MAXIMUM_SIZE: Int = 64

class ConstantTimeTest : FunSpec({
    test("equality agrees with content equality for any pair of arrays") {
        val arrays = Arb.byteArray(length = Arb.int(0..MAXIMUM_SIZE), content = Arb.byte())
        checkAll(genA = arrays, genB = arrays) { first, second ->
            val isEqual = first.contentEquals(second)
            ConstantTime.equals(first = first, second = second) shouldBe isEqual
            ConstantTime.equals(first = ByteString(first), second = ByteString(second)) shouldBe isEqual
            ConstantTime.equals(first = first, second = first.copyOf()) shouldBe true
        }
    }

    test("arrays that differ only in length are unequal") {
        ConstantTime.equals(first = byteArrayOf(1), second = byteArrayOf(1, 0)) shouldBe false
        ConstantTime.equals(first = ByteString(1), second = ByteString(1, 0)) shouldBe false
    }

    test("select picks without a branch") {
        checkAll(genA = Arb.boolean(), genB = Arb.int(), genC = Arb.int()) { condition, first, second ->
            val expected = when (condition) {
                true -> first
                false -> second
            }
            ConstantTime.select(condition = condition, whenTrue = first, whenFalse = second) shouldBe expected
        }
    }
})
