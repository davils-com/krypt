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

import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.core.io.readAll
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.core.policy.CryptoPolicy
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class AuditCoreTest : FunSpec({
    test("A-4: the Cnsa2 profile protects only with SHA-384 and SHA-512 as its documentation promises") {
        val policy = CryptoPolicy.Cnsa2
        policy.permits(MacAlgorithm.HmacSha256, AlgorithmUse.Protect) shouldBe false
        policy.permits(KdfAlgorithm.HkdfSha256, AlgorithmUse.Protect) shouldBe false
        policy.permits(KdfAlgorithm.Pbkdf2Sha256, AlgorithmUse.Protect) shouldBe false
        policy.permits(DigestAlgorithm.Sha3384, AlgorithmUse.Protect) shouldBe false
    }

    test("A-12: readAll with the largest limit reads a short source instead of failing to allocate") {
        val source = byteArrayOf(1, 2, 3).asByteSource()
        shouldNotThrowAny { source.readAll(Int.MAX_VALUE).size } shouldBe 3
    }
})
