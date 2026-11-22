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

package com.davils.krypt.primitive.key

import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class KeyGenerationPolicyTest : FunSpec({
    test("a key is generated only when the policy permits an algorithm that uses it for something new") {
        val noX25519 = Crypto(
            environment {
                policy = cryptoPolicy { forbid(KeyAgreementAlgorithm.X25519, KemAlgorithm.DhkemX25519) }
            },
        )
        shouldThrow<PolicyViolationException> { noX25519.keys.generate(KeyType.X25519) }
        val ed25519 = noX25519.keys.generate(KeyType.Ed25519)
        ed25519.publicKey.family shouldBe KeyFamily.Ed25519
        val dhkemOnly = Crypto(environment { policy = cryptoPolicy { forbid(KeyAgreementAlgorithm.X25519) } })
        val x25519 = dhkemOnly.keys.generate(KeyType.X25519)
        x25519.publicKey.family shouldBe KeyFamily.X25519
        val noRsa = Crypto(
            environment {
                policy = cryptoPolicy {
                    forbid(
                        SignatureAlgorithm.RsaPssSha256,
                        SignatureAlgorithm.RsaPssSha384,
                        SignatureAlgorithm.RsaPssSha512,
                        AsymmetricEncryptionAlgorithm.RsaOaepSha256,
                        AsymmetricEncryptionAlgorithm.RsaOaepSha384,
                        AsymmetricEncryptionAlgorithm.RsaOaepSha512,
                    )
                }
            },
        )
        shouldThrow<PolicyViolationException> { noRsa.keys.generate(KeyType.Rsa3072) }
        val noMlKem = Crypto(
            environment { policy = cryptoPolicy { forbid(KemAlgorithm.MlKem768, KemAlgorithm.MlKem1024) } },
        )
        shouldThrow<PolicyViolationException> { noMlKem.keys.generate(KeyType.MlKem768) }
        val cnsa = Crypto(environment { policy = CryptoPolicy.Cnsa2 })
        shouldThrow<PolicyViolationException> { cnsa.keys.generate(KeyType.Rsa3072) }
    }
})
