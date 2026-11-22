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

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

private const val DRAWN: Int = 33

class RandomSourceTest : FunSpec({
    test("the secure source fills arrays of every length") {
        val first = RandomSource.Secure.bytes(DRAWN)
        val second = RandomSource.Secure.bytes(DRAWN)
        first.size shouldBe DRAWN
        first.contentEquals(second) shouldNotBe true
        RandomSource.Secure.bytes(0).size shouldBe 0
    }

    test("a negative count is refused") {
        shouldThrow<IllegalArgumentException> { RandomSource.Secure.bytes(-1) }
    }
})
