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

package com.davils.krypt.keyset

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString

private const val LOW: String = "0001020304050607"
private const val HIGH: String = "f001020304050607"

class KeyIdTest : FunSpec({
    test("an id is eight bytes shown in hex") {
        val id = checkNotNull(KeyId.parseOrNull(LOW))
        id.hex shouldBe LOW
        id.toString() shouldBe LOW
        id.bytes.size shouldBe KeyId.SIZE
        KeyId.of(id.bytes) shouldBe id
        id.hashCode() shouldBe id.bytes.hashCode()
        id shouldNotBe checkNotNull(KeyId.parseOrNull(HIGH))
        id shouldBeLessThan checkNotNull(KeyId.parseOrNull(HIGH))
    }

    test("anything but eight bytes is no id") {
        KeyId.parseOrNull("00") shouldBe null
        KeyId.parseOrNull("zz01020304050607") shouldBe null
        shouldThrow<IllegalArgumentException> { KeyId.of(ByteString(1, 2)) }
    }
})
