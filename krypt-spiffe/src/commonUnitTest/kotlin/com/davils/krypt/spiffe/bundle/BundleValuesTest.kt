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

package com.davils.krypt.spiffe.bundle

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.spiffe.fixture.Authority
import com.davils.krypt.spiffe.fixture.DOMAIN
import com.davils.krypt.spiffe.fixture.DOMAIN_ID
import com.davils.krypt.spiffe.fixture.FixedClock
import com.davils.krypt.spiffe.fixture.crypto
import com.davils.krypt.spiffe.fixture.domain
import com.davils.krypt.spiffe.fixture.foreign
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.path.TrustAnchor
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private const val KEY_ID: String = "key-1"
private const val OTHER_KEY_ID: String = "key-2"

class BundleValuesTest : FunSpec({
    test("a JWT authority checks its key id and compares by key id and key") {
        val key = crypto.keys.generate(KeyType.P256).publicKey
        val other = crypto.keys.generate(KeyType.P256).publicKey
        val authority = JwtAuthority(KEY_ID, key)
        authority shouldBe JwtAuthority(KEY_ID, key)
        authority.hashCode() shouldBe JwtAuthority(KEY_ID, key).hashCode()
        authority shouldNotBe JwtAuthority(OTHER_KEY_ID, key)
        authority shouldNotBe JwtAuthority(KEY_ID, other)
        authority.equals(KEY_ID) shouldBe false
        authority.toString() shouldContain KEY_ID
        JwtAuthority("k".repeat(JwtAuthority.MAXIMUM_KEY_ID_LENGTH), key).keyId.length shouldBe
            JwtAuthority.MAXIMUM_KEY_ID_LENGTH
        shouldThrow<IllegalArgumentException> { JwtAuthority("", key) }
        shouldThrow<IllegalArgumentException> { JwtAuthority("k".repeat(JwtAuthority.MAXIMUM_KEY_ID_LENGTH + 1), key) }
    }

    test("a bundle checks its sequence, refresh hint, key ids, keys and size") {
        val key = crypto.keys.generate(KeyType.P256).publicKey
        val maximum = JsonValue.Integer.MAXIMUM
        TrustBundle(domain, sequence = 0L, refreshHint = 0.seconds).sequence shouldBe 0L
        val longest = TrustBundle.MAXIMUM_REFRESH_HINT_SECONDS.seconds
        TrustBundle(domain, sequence = maximum, refreshHint = longest).refreshHint shouldBe longest
        shouldThrow<IllegalArgumentException> { TrustBundle(domain, sequence = -1L) }
        shouldThrow<IllegalArgumentException> { TrustBundle(domain, sequence = maximum + 1) }
        shouldThrow<IllegalArgumentException> { TrustBundle(domain, refreshHint = (-1).seconds) }
        shouldThrow<IllegalArgumentException> { TrustBundle(domain, refreshHint = 1_500.milliseconds) }
        shouldThrow<IllegalArgumentException> { TrustBundle(domain, refreshHint = longest + 1.seconds) }
        val twice = listOf(JwtAuthority(KEY_ID, key), JwtAuthority(KEY_ID, key))
        shouldThrow<IllegalArgumentException> { TrustBundle(domain, jwtAuthorities = twice) }
        val many = (0..SpiffeLimits.HARD_MAXIMUM_AUTHORITIES).map { index -> JwtAuthority("k$index", key) }
        shouldThrow<IllegalArgumentException> { TrustBundle(domain, jwtAuthorities = many) }
        TrustBundle(domain, jwtAuthorities = many.drop(1)).jwtAuthorities.size shouldBe
            SpiffeLimits.HARD_MAXIMUM_AUTHORITIES
        val root = Authority.root(DOMAIN_ID)
        val strict = Crypto(
            environment {
                clock = FixedClock
                policy = CryptoPolicy.Cnsa2
            },
        )
        val encoded = root.certificate.encoded
        val decoded = Certificates(strict).decode(encoded)
        val unusable = decoded.getOrNull() ?: error("certificate")
        unusable.publicKey.shouldBeNull()
        shouldThrow<IllegalArgumentException> { TrustBundle(domain, x509Authorities = listOf(unusable)) }
    }

    test("a bundle looks up JWT authorities and turns X.509 authorities into anchors") {
        val key = crypto.keys.generate(KeyType.P256).publicKey
        val root = Authority.root(DOMAIN_ID)
        val bundle = TrustBundle(domain, listOf(root.certificate), listOf(JwtAuthority(KEY_ID, key)))
        bundle.jwtAuthority(KEY_ID) shouldBe JwtAuthority(KEY_ID, key)
        bundle.jwtAuthority(OTHER_KEY_ID).shouldBeNull()
        bundle.trustAnchors() shouldBe listOf(TrustAnchor.of(root.certificate))
        bundle.isEmpty shouldBe false
        TrustBundle(domain, jwtAuthorities = listOf(JwtAuthority(KEY_ID, key))).isEmpty shouldBe false
        TrustBundle(domain).isEmpty shouldBe true
    }

    test("bundles compare by every field") {
        val key = crypto.keys.generate(KeyType.P256).publicKey
        val root = Authority.root(DOMAIN_ID)
        val jwt = listOf(JwtAuthority(KEY_ID, key))
        val roots = listOf(root.certificate)

        fun bundle(
            trustDomain: TrustDomain = domain,
            x509: List<Certificate> = roots,
            keys: List<JwtAuthority> = jwt,
            sequence: Long = 1L,
            hint: Duration = 1.seconds,
        ): TrustBundle = TrustBundle(
            trustDomain = trustDomain,
            x509Authorities = x509,
            jwtAuthorities = keys,
            sequence = sequence,
            refreshHint = hint,
        )
        val first = bundle()
        first shouldBe bundle()
        first.hashCode() shouldBe bundle().hashCode()
        first.equals(domain) shouldBe false
        first shouldNotBe bundle(trustDomain = foreign)
        first shouldNotBe bundle(x509 = emptyList())
        first shouldNotBe bundle(keys = emptyList())
        first shouldNotBe bundle(sequence = 2L)
        first shouldNotBe bundle(hint = 2.seconds)
        first.toString() shouldContain DOMAIN
        TrustBundle(domain).toString() shouldContain "none"
    }

    test("a bundle set holds one bundle per trust domain, ordered, bounded and replaceable") {
        val first = TrustBundle(domain, sequence = 1L)
        val second = TrustBundle(domain, sequence = 2L)
        val other = TrustBundle(foreign)
        val set = BundleSet(listOf(first, other))
        val unknown = TrustDomain.of("example.net")
        set.size shouldBe 2
        set.trustDomains shouldBe listOf(foreign, domain)
        set.bundles shouldBe listOf(other, first)
        set[domain] shouldBe first
        set.bundle(domain) shouldBe first
        (domain in set) shouldBe true
        (unknown in set) shouldBe false
        set[unknown].shouldBeNull()
        set.with(second)[domain] shouldBe second
        set.with(second).size shouldBe 2
        set.without(domain).trustDomains shouldBe listOf(foreign)
        set.without(unknown) shouldBe set
        set shouldBe BundleSet(listOf(other, first))
        set.hashCode() shouldBe BundleSet(listOf(other, first)).hashCode()
        set shouldNotBe set.with(second)
        set.equals(first) shouldBe false
        set.toString() shouldContain DOMAIN
        BundleSet.Empty.size shouldBe 0
        shouldThrow<IllegalArgumentException> { BundleSet(listOf(first, second)) }
        val many = (0..SpiffeLimits.HARD_MAXIMUM_TRUST_DOMAINS).map { index -> TrustBundle(TrustDomain.of("d$index")) }
        shouldThrow<IllegalArgumentException> { BundleSet(many) }
        BundleSet(many.drop(1)).size shouldBe SpiffeLimits.HARD_MAXIMUM_TRUST_DOMAINS
    }
})
