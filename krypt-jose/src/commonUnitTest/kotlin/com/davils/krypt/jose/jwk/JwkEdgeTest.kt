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

package com.davils.krypt.jose.jwk

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.fixture.crypto
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.keys
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.primitive.Crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain

class JwkEdgeTest : FunSpec({
    test("compares the parameters of keys with the same metadata") {
        val first = keys.of(crypto.keys.generate(KeyType.P256).publicKey)
        val second = keys.of(crypto.keys.generate(KeyType.P256).publicKey)
        first shouldNotBe second
        keys.of(crypto.keys.generateSecret()).toString() shouldContain "crv=none"
    }

    test("refuses a private key the policy does not let prove itself") {
        val verifyOnly = cryptoPolicy {
            forbid(SignatureAlgorithm.EcdsaSha256)
            accept(SignatureAlgorithm.EcdsaSha256)
        }
        val restricted = JsonWebKeys(Crypto(environment { policy = verifyOnly }))
        val jwk = keys.of(crypto.keys.generate(KeyType.P256).privateKey)
        restricted.privateKey(jwk).failure() shouldBe JoseFailure.InvalidKey
        keys.privateKey(jwk).value().publicKey shouldBe keys.publicKey(jwk).value()
    }
})
