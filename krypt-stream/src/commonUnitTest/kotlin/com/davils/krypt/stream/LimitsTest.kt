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

package com.davils.krypt.stream

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class LimitsTest : FunSpec({
    test("limits are checked against their ceilings and compared") {
        val limits = StreamLimits()
        limits shouldBe StreamLimits.Default
        limits shouldNotBe StreamLimits(maximumRecipients = 1)
        limits shouldNotBe StreamLimits(maximumSegments = 1L)
        limits shouldNotBe StreamLimits(maximumSignatures = 1)
        limits shouldNotBe StreamLimits(maximumIterations = 1)
        limits shouldNotBe Any()
        limits.hashCode() shouldBe StreamLimits().hashCode()
        limits.toString() shouldBe "StreamLimits(maximumRecipients=16, maximumSegments=4294967295, " +
            "maximumSignatures=32, maximumIterations=10000000)"
        shouldThrow<IllegalArgumentException> { StreamLimits(maximumRecipients = 0) }
        shouldThrow<IllegalArgumentException> {
            StreamLimits(
                maximumRecipients = StreamLimits.HARD_MAXIMUM_RECIPIENTS + 1,
            )
        }
        shouldThrow<IllegalArgumentException> { StreamLimits(maximumSegments = 0L) }
        shouldThrow<IllegalArgumentException> { StreamLimits(maximumSegments = StreamLimits.HARD_MAXIMUM_SEGMENTS + 1) }
        shouldThrow<IllegalArgumentException> { StreamLimits(maximumSignatures = 0) }
        shouldThrow<IllegalArgumentException> {
            StreamLimits(
                maximumSignatures = StreamLimits.HARD_MAXIMUM_SIGNATURES + 1,
            )
        }
        shouldThrow<IllegalArgumentException> { StreamLimits(maximumIterations = 0) }
        StreamSuite.Aes256Gcm.id shouldBe 1
    }
})
