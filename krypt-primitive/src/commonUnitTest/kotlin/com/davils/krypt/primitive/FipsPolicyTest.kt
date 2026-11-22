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

package com.davils.krypt.primitive

import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.core.policy.cryptoPolicy
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.encodeToByteString

class FipsPolicyTest : FunSpec({
    test("a policy that demands a FIPS provider refuses every operation in an environment that names none") {
        val fips = Crypto(environment { policy = CryptoPolicy.Fips })
        fips.capabilities.supports(DigestAlgorithm.Sha256) shouldBe true
        val refused = shouldThrow<CryptoException> { fips.digests.digest("message".encodeToByteString()) }
        refused.message.orEmpty() shouldContain "FIPS validated provider"
        val custom = Crypto(environment { policy = cryptoPolicy { isFipsProviderRequired = true } })
        shouldThrow<CryptoException> { custom.keys.generate(KeyType.P256) }
    }
})
