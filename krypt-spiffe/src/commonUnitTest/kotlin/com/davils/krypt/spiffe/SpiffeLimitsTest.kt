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

package com.davils.krypt.spiffe

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain

class SpiffeLimitsTest : FunSpec({
    test("every limit accepts 1 and its hard ceiling and refuses 0 and one past the ceiling") {
        val builders: List<(Int) -> SpiffeLimits> = listOf(
            { value -> SpiffeLimits(maximumBytes = value) },
            { value -> SpiffeLimits(maximumAuthorities = value) },
            { value -> SpiffeLimits(maximumTrustDomains = value) },
            { value -> SpiffeLimits(maximumChainLength = value) },
            { value -> SpiffeLimits(maximumTokenBytes = value) },
            { value -> SpiffeLimits(maximumSvids = value) },
        )
        val ceilings = listOf(
            SpiffeLimits.HARD_MAXIMUM_BYTES,
            SpiffeLimits.HARD_MAXIMUM_AUTHORITIES,
            SpiffeLimits.HARD_MAXIMUM_TRUST_DOMAINS,
            SpiffeLimits.HARD_MAXIMUM_CHAIN_LENGTH,
            SpiffeLimits.HARD_MAXIMUM_TOKEN_BYTES,
            SpiffeLimits.HARD_MAXIMUM_SVIDS,
        )
        builders.zip(ceilings).forEach { (build, ceiling) ->
            build(1) shouldNotBe SpiffeLimits.Default
            build(ceiling) shouldNotBe SpiffeLimits.Default
            shouldThrow<IllegalArgumentException> { build(0) }
            shouldThrow<IllegalArgumentException> { build(ceiling + 1) }
        }
    }

    test("limits compare by every value") {
        SpiffeLimits() shouldBe SpiffeLimits.Default
        SpiffeLimits().hashCode() shouldBe SpiffeLimits.Default.hashCode()
        SpiffeLimits.Default.equals("limits") shouldBe false
        SpiffeLimits.Default.toString() shouldContain "maximumTokenBytes=${SpiffeLimits.DEFAULT_MAXIMUM_TOKEN_BYTES}"
    }
})
