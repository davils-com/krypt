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

package com.davils.krypt.testing

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString

private const val SEED: Long = 7L
private const val ODD_LENGTH: Int = 13
private const val LONG_LENGTH: Int = 64
private const val FIRST: Byte = 1
private const val SECOND: Byte = 2
private const val THIRD: Byte = 3

class RandomTest : FunSpec({
    test("a seeded source repeats its sequence and differs by seed") {
        val first = SeededRandom(SEED).bytes(ODD_LENGTH)
        val second = SeededRandom(SEED).bytes(ODD_LENGTH)
        first.toList() shouldBe second.toList()
        val other = SeededRandom(SEED + 1).bytes(ODD_LENGTH)
        other.toList() shouldNotBe first.toList()
        val source = SeededRandom(SEED)
        source.bytes(LONG_LENGTH).toList() shouldNotBe source.bytes(LONG_LENGTH).toList()
        source.bytes(0).size shouldBe 0
        source.toString() shouldBe "SeededRandom(seed=7)"
        source.seed shouldBe SEED
    }

    test("a replayed source hands out its bytes once, in order") {
        val source = ReplayedRandom(ByteString(FIRST, SECOND, THIRD))
        source.bytes(2).toList() shouldBe listOf(FIRST, SECOND)
        source.remaining shouldBe 1
        source.toString() shouldBe "ReplayedRandom(remaining=1)"
        source.bytes(1).toList() shouldBe listOf(THIRD)
        shouldThrow<IllegalStateException> { source.bytes(1) }
    }
})
