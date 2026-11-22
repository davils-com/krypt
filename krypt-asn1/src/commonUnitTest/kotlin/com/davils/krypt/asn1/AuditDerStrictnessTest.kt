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

package com.davils.krypt.asn1

import com.davils.krypt.asn1.fixture.hex
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class AuditDerStrictnessTest : FunSpec({
    test("A-7: an OBJECT IDENTIFIER whose subidentifier is padded with 0x80 is refused") {
        val padded = Der.decode(hex("06032a8001")) { readObjectIdentifier() }
        padded.isSuccess shouldBe false
        val paddedFirst = Der.decode(hex("0602802a")) { readObjectIdentifier() }
        paddedFirst.isSuccess shouldBe false
        ObjectIdentifier.decodeOrNull(hex("2a8001")) shouldBe null
    }

    test("A-8: a SET OF whose elements are not sorted by their encoding is refused") {
        val unsorted = Der.decode(hex("3106020102020101")) { readSet { readRemaining().size } }
        unsorted.isSuccess shouldBe false
    }
})
