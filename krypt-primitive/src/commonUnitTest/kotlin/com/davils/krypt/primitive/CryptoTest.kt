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

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.primitive.fixture.crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

private const val ED448: String = "Ed448"

class CryptoTest : FunSpec({
    test("the capabilities answer for the algorithms every platform has") {
        crypto.capabilities.supports(DigestAlgorithm.Sha256) shouldBe true
        crypto.capabilities.supports(MacAlgorithm.HmacSha256) shouldBe true
        crypto.capabilities.supports(AeadAlgorithm.Aes256Gcm) shouldBe true
        crypto.capabilities.supports(KeyType.P256) shouldBe true
        crypto.capabilities.supports(DigestAlgorithm.Sha256) shouldBe true
    }

    test("verifications and exceptions describe themselves") {
        Verification.of(true) shouldBe Verification.Valid
        Verification.of(false) shouldBe Verification.Invalid
        Verification.Invalid.isValid shouldBe false
        val unsupported = UnsupportedAlgorithmException(ED448)
        unsupported.message shouldContain ED448
        unsupported.algorithmName shouldBe ED448
        PolicyViolationException("MD5").message shouldContain "MD5"
        crypto.toString() shouldContain "Modern"
    }
})
