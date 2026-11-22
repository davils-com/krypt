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

package com.davils.krypt.core.algorithm

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeUnique
import io.kotest.matchers.shouldBe

private const val RSA_BITS: Int = 2_048

class AlgorithmTest : FunSpec({
    val algorithms: List<Algorithm> = DigestAlgorithm.entries +
        MacAlgorithm.entries +
        AeadAlgorithm.entries +
        KeyWrapAlgorithm.entries +
        KdfAlgorithm.entries +
        SignatureAlgorithm.entries +
        KeyAgreementAlgorithm.entries +
        AsymmetricEncryptionAlgorithm.entries +
        KemAlgorithm.entries

    test("every algorithm has a unique canonical name") {
        algorithms.map { algorithm -> algorithm.algorithmName }.shouldBeUnique()
    }

    test("a legacy algorithm is never approved and never post-quantum") {
        algorithms.filter { algorithm -> algorithm.isLegacy }.forEach { algorithm ->
            algorithm.isFipsApproved shouldBe false
            algorithm.isPostQuantum shouldBe false
            algorithm.securityBits shouldBe 0
        }
    }

    test("the facts of a signature, a key agreement and a KEM are consistent") {
        SignatureAlgorithm.EcdsaSha384.digest shouldBe DigestAlgorithm.Sha384
        SignatureAlgorithm.Ed25519.digest shouldBe null
        SignatureAlgorithm.MlDsa65.isPostQuantum shouldBe true
        KeyAgreementAlgorithm.EcdhP384.curve shouldBe EllipticCurve.P384
        KemAlgorithm.MlKem768.family shouldBe KeyFamily.MlKem
        MacAlgorithm.HmacSha512.tagBytes shouldBe DigestAlgorithm.Sha512.outputBytes
    }

    test("every key type names its family, size and curve") {
        KeyType.entries.forEach { type ->
            (type.curve != null) shouldBe (type.family == KeyFamily.Ec)
            (type.bits > 0) shouldBe true
        }
        KeyType.Rsa2048.bits shouldBe RSA_BITS
        KeyType.P521.curve shouldBe EllipticCurve.P521
        EllipticCurve.P256.objectIdentifier shouldBe "1.2.840.10045.3.1.7"
    }
})
