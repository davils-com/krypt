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

package com.davils.krypt.keystore

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.keystore.fixture.crypto
import com.davils.krypt.keystore.fixture.identity
import com.davils.krypt.keystore.fixture.issue
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificates
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain

class IdentitiesTest : FunSpec({
    val identities = Identities(crypto)

    test("the chain follows the issuers and leaves out the rest") {
        val root = issue(name = "Root", isCa = true)
        val intermediate = issue(name = "Intermediate", issuer = root, isCa = true)
        val leaf = issue(name = "leaf", issuer = intermediate)
        val stranger = issue(name = "Stranger", isCa = true)
        val shuffled = listOf(stranger.certificate, root.certificate, leaf.certificate, intermediate.certificate)
        val identity = checkNotNull(identities.of(leaf.pair.privateKey, shuffled).getOrNull())
        identity.chain shouldBe listOf(leaf.certificate, intermediate.certificate, root.certificate)
        identity.certificate shouldBe leaf.certificate
        identity.privateKey shouldBe leaf.pair.privateKey
        identity.toString() shouldContain "chain=3"
        identity.hashCode() shouldBe identity.chain.hashCode()
        identity shouldNotBe leaf
        identity shouldNotBe checkNotNull(identities.of(leaf.pair.privateKey, listOf(leaf.certificate)).getOrNull())
        identities.toString() shouldContain "Identities"
    }

    test("a key without its certificate forms no identity") {
        val leaf = issue(name = "leaf")
        val other = issue(name = "other")
        val rsa = issue(name = "rsa", type = KeyType.Rsa3072)
        identities.of(leaf.pair.privateKey, emptyList()).failureOrNull() shouldBe IdentityFailure.NoCertificate
        identities.of(leaf.pair.privateKey, listOf(other.certificate, rsa.certificate)).failureOrNull() shouldBe
            IdentityFailure.KeyMismatch
        val noP256 = Certificates(Crypto(environment { policy = cryptoPolicy { curves(EllipticCurve.P384) } }))
        val unreadable = checkNotNull(noP256.decode(leaf.certificate.encoded).getOrNull())
        identities.of(leaf.pair.privateKey, listOf(unreadable)).failureOrNull() shouldBe IdentityFailure.KeyMismatch
    }

    test("limits refuse values past their ceilings and compare by value") {
        shouldThrow<IllegalArgumentException> { KeystoreLimits(maximumBytes = KeystoreLimits.HARD_MAXIMUM_BYTES + 1) }
        shouldThrow<IllegalArgumentException> { KeystoreLimits(maximumBytes = 0) }
        shouldThrow<IllegalArgumentException> {
            KeystoreLimits(maximumEntries = KeystoreLimits.HARD_MAXIMUM_ENTRIES + 1)
        }
        shouldThrow<IllegalArgumentException> { KeystoreLimits(maximumEntries = 0) }
        shouldThrow<IllegalArgumentException> {
            KeystoreLimits(maximumMacIterations = KeystoreLimits.HARD_MAXIMUM_MAC_ITERATIONS + 1)
        }
        shouldThrow<IllegalArgumentException> { KeystoreLimits(maximumMacIterations = 0) }
        KeystoreLimits() shouldBe KeystoreLimits.Default
        KeystoreLimits().hashCode() shouldBe KeystoreLimits.Default.hashCode()
        KeystoreLimits(maximumEntries = 1) shouldNotBe KeystoreLimits.Default
        KeystoreLimits.Default shouldNotBe identity().first
        KeystoreLimits.Default.toString() shouldContain "maximumMacIterations=100000"
    }
})
