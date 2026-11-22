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

package com.davils.krypt.jose

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.utf8
import com.davils.krypt.jose.fixture.value
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class StrictJsonTest : FunSpec({
    test("reads values and objects") {
        StrictJson.decode(utf8("[1]")).value() shouldBe JsonValue.Array(listOf(JsonValue.Integer(1)))
        val expected = JsonValue.Object.of("a" to JsonValue.Bool(true))
        StrictJson.decodeObject(utf8("""{"a":true}""")).value() shouldBe expected
    }

    test("refuses what is no object and what passes the limits") {
        StrictJson.decodeObject(utf8("[]")).failure() shouldBe JoseFailure.Malformed
        StrictJson.decode(utf8("[1.5]")).failure() shouldBe JoseFailure.Malformed
        val limits = JoseLimits(maximumBytes = 2)
        StrictJson.decode(bytes = utf8("[1]"), limits = limits).failure() shouldBe JoseFailure.LimitExceeded
        StrictJson.decodeObject(bytes = utf8("{}"), limits = limits).value() shouldBe JsonValue.Object.Empty
    }
})
