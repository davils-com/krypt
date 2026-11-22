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

package com.davils.krypt.spiffe.jwt

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.JwtAuthority
import com.davils.krypt.spiffe.bundle.TrustBundle
import com.davils.krypt.spiffe.fixture.AUDIENCE
import com.davils.krypt.spiffe.fixture.FOREIGN_WORKLOAD
import com.davils.krypt.spiffe.fixture.Minted
import com.davils.krypt.spiffe.fixture.Minted.Companion.KEY_ID
import com.davils.krypt.spiffe.fixture.MovedClock
import com.davils.krypt.spiffe.fixture.NOW
import com.davils.krypt.spiffe.fixture.WORKLOAD
import com.davils.krypt.spiffe.fixture.compatible
import com.davils.krypt.spiffe.fixture.crypto
import com.davils.krypt.spiffe.fixture.domain
import com.davils.krypt.spiffe.fixture.failureOf
import com.davils.krypt.spiffe.fixture.foreign
import com.davils.krypt.spiffe.fixture.svidOf
import com.davils.krypt.spiffe.fixture.value
import com.davils.krypt.spiffe.fixture.workload
import com.davils.krypt.spiffe.source.BundleSource
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private const val OTHER_AUDIENCE: String = "billing"
private const val ROLE: String = "role"
private const val ADMIN: String = "admin"
private const val PARTS: Int = 3

private val LIFETIME: Duration = 5.minutes

private fun bundlesWith(key: JwtAuthority): BundleSet =
    BundleSet(listOf(TrustBundle(domain, jwtAuthorities = listOf(key))))

class JwtSvidTest : FunSpec({
    test("a signed JWT-SVID validates for its audience and carries its claims") {
        val minted = Minted.of()
        val claims = JsonValue.Object.of(ROLE to JsonValue.Text(ADMIN))
        val signer = minted.signer
        val svid = signer.sign(subject = workload, audience = listOf(AUDIENCE), lifetime = LIFETIME, claims = claims)
        svid.id shouldBe workload
        svid.audience shouldBe listOf(AUDIENCE)
        svid.expiresAt shouldBe NOW + LIFETIME
        svid.toString() shouldNotContain svid.token
        val token = svid.token
        token.split('.').size shouldBe PARTS
        val validated = JwtSvidValidator(crypto, minted.bundles).svidOf(svid.token)
        validated shouldBe svid
        validated.hashCode() shouldBe svid.hashCode()
        validated.claims[ROLE] shouldBe JsonValue.Text(ADMIN)
        validated.expiresAt shouldBe svid.expiresAt
        validated.id shouldBe workload
        validated.equals(svid.token) shouldBe false
        validated shouldNotBe signer.sign(workload, listOf(AUDIENCE), LIFETIME)
    }

    test("RSA-PSS, ECDSA and, under a compatible policy, RSASSA-PKCS1-v1_5 tokens validate") {
        val cases = listOf(
            Triple(first = KeyType.Rsa3072, second = JwsAlgorithm.PS256, third = crypto),
            Triple(first = KeyType.P384, second = JwsAlgorithm.ES384, third = crypto),
            Triple(first = KeyType.P521, second = JwsAlgorithm.ES512, third = crypto),
            Triple(first = KeyType.Rsa3072, second = JwsAlgorithm.RS256, third = compatible),
        )
        cases.forEach { (type, algorithm, engine) ->
            val minted = Minted.of(type = type, algorithm = algorithm, engine = engine)
            val token = minted.token(audience = listOf(OTHER_AUDIENCE, AUDIENCE))
            val validated = JwtSvidValidator(engine, minted.bundles).svidOf(token)
            validated.audience shouldBe listOf(OTHER_AUDIENCE, AUDIENCE)
        }
    }

    test("the audience, the expiry and the clock skew are checked") {
        val minted = Minted.of()
        val bundles = minted.bundles
        val token = minted.token()
        val validator = JwtSvidValidator(crypto, bundles)
        validator.failureOf(token = token, audience = OTHER_AUDIENCE) shouldBe JwtSvidFailure.WrongAudience
        val skewed = MovedClock.cryptoAt(NOW + LIFETIME + 10.seconds)
        val lenient = JwtSvidValidator(skewed, bundles).svidOf(token)
        lenient.id shouldBe workload
        JwtSvidValidator(skewed, bundles, clockSkew = Duration.ZERO).failureOf(token) shouldBe JwtSvidFailure.Expired
        val late = MovedClock.cryptoAt(NOW + LIFETIME + 1.minutes)
        JwtSvidValidator(late, bundles).failureOf(token) shouldBe JwtSvidFailure.Expired
        val early = MovedClock.cryptoAt(NOW - 10.minutes)
        JwtSvidValidator(early, bundles).failureOf(token) shouldBe JwtSvidFailure.NotYetValid
    }

    test("the key is looked up by kid in the bundle of the trust domain of the subject only") {
        val minted = Minted.of()
        val token = minted.token()
        JwtSvidValidator(crypto, BundleSet()).failureOf(token) shouldBe JwtSvidFailure.NoBundle
        val broken = BundleSource { _ -> error("The Workload API is gone") }
        JwtSvidValidator(crypto, broken).failureOf(token) shouldBe JwtSvidFailure.NoBundle
        val otherKey = crypto.keys.generate(KeyType.P256).publicKey
        val renamed = bundlesWith(JwtAuthority("other", otherKey))
        JwtSvidValidator(crypto, renamed).failureOf(token) shouldBe JwtSvidFailure.KeyNotFound
        val swapped = bundlesWith(JwtAuthority(KEY_ID, otherKey))
        JwtSvidValidator(crypto, swapped).failureOf(token) shouldBe JwtSvidFailure.BadSignature
        val rsa = crypto.keys.generate(KeyType.Rsa3072).publicKey
        val mismatched = bundlesWith(JwtAuthority(KEY_ID, rsa))
        JwtSvidValidator(crypto, mismatched).failureOf(token) shouldBe JwtSvidFailure.KeyNotFound
        val foreignId = SpiffeId.parse(FOREIGN_WORKLOAD).value()
        val forged = minted.token(subject = foreignId)
        JwtSvidValidator(crypto, minted.bundles).failureOf(forged) shouldBe JwtSvidFailure.NoBundle
        val foreignBundle = TrustBundle(foreign, jwtAuthorities = listOf(JwtAuthority(KEY_ID, otherKey)))
        val federated = minted.bundles.with(foreignBundle)
        JwtSvidValidator(crypto, federated).failureOf(forged) shouldBe JwtSvidFailure.BadSignature
    }

    test("the validator checks its configuration") {
        val minted = Minted.of()
        val bundles = minted.bundles
        shouldThrow<IllegalArgumentException> { JwtSvidValidator(crypto, bundles, clockSkew = (-1).seconds) }
        shouldThrow<IllegalArgumentException> { JwtSvidValidator(crypto, bundles, clockSkew = 6.minutes) }
        shouldThrow<IllegalArgumentException> { JwtSvidValidator(crypto, bundles, algorithms = emptySet()) }
        shouldThrow<IllegalArgumentException> {
            JwtSvidValidator(crypto, bundles, algorithms = setOf(JwsAlgorithm.HS256))
        }
        val narrow = JwtSvidValidator(crypto, bundles, algorithms = setOf(JwsAlgorithm.PS256))
        narrow.algorithms shouldBe setOf(JwsAlgorithm.PS256)
        narrow.toString() shouldContain "PS256"
        val token = minted.token()
        narrow.failureOf(token) shouldBe JwtSvidFailure.UnsupportedAlgorithm
        shouldThrow<IllegalArgumentException> { narrow.failureOf(token = token, audience = "") }
    }

    test("the signer checks its configuration and every token it signs") {
        val minted = Minted.of()
        val key = minted.pair.privateKey
        val longKeyId = "k".repeat(JwtAuthority.MAXIMUM_KEY_ID_LENGTH + 1)
        shouldThrow<IllegalArgumentException> {
            JwtSvidSigner(crypto = crypto, key = key, keyId = KEY_ID, algorithm = JwsAlgorithm.EdDSA)
        }
        shouldThrow<IllegalArgumentException> {
            JwtSvidSigner(crypto = crypto, key = key, keyId = "", algorithm = JwsAlgorithm.ES256)
        }
        shouldThrow<IllegalArgumentException> {
            JwtSvidSigner(crypto = crypto, key = key, keyId = longKeyId, algorithm = JwsAlgorithm.ES256)
        }
        val signer = minted.signer
        signer.keyId shouldBe KEY_ID
        signer.algorithm shouldBe JwsAlgorithm.ES256
        signer.toString() shouldContain KEY_ID
        signer.toString() shouldNotContain key.toString()
        shouldThrow<IllegalArgumentException> { signer.sign(workload, emptyList(), LIFETIME) }
        shouldThrow<IllegalArgumentException> { signer.sign(workload, listOf(AUDIENCE, ""), LIFETIME) }
        shouldThrow<IllegalArgumentException> { signer.sign(workload, listOf(AUDIENCE), Duration.ZERO) }
        shouldThrow<IllegalArgumentException> { signer.sign(workload, listOf(AUDIENCE), 1.days + 1.seconds) }
        val longest = signer.sign(subject = workload, audience = listOf(AUDIENCE), lifetime = 1.days)
        longest.expiresAt shouldBe NOW + 1.days
        val registered = JsonValue.Object.of("sub" to JsonValue.Text(WORKLOAD))
        shouldThrow<IllegalArgumentException> {
            signer.sign(subject = workload, audience = listOf(AUDIENCE), lifetime = LIFETIME, claims = registered)
        }
    }
})
