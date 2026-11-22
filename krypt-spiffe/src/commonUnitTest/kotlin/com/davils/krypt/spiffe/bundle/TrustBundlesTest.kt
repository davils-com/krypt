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

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.fixture.Authority
import com.davils.krypt.spiffe.fixture.DOMAIN_ID
import com.davils.krypt.spiffe.fixture.FOREIGN_DOMAIN_ID
import com.davils.krypt.spiffe.fixture.FixedClock
import com.davils.krypt.spiffe.fixture.JWT_USE
import com.davils.krypt.spiffe.fixture.X509_USE
import com.davils.krypt.spiffe.fixture.array
import com.davils.krypt.spiffe.fixture.bundleOf
import com.davils.krypt.spiffe.fixture.chainOf
import com.davils.krypt.spiffe.fixture.codec
import com.davils.krypt.spiffe.fixture.crypto
import com.davils.krypt.spiffe.fixture.domain
import com.davils.krypt.spiffe.fixture.entry
import com.davils.krypt.spiffe.fixture.failure
import com.davils.krypt.spiffe.fixture.failureOf
import com.davils.krypt.spiffe.fixture.foreign
import com.davils.krypt.spiffe.fixture.jsonWebKeys
import com.davils.krypt.spiffe.fixture.jwkOf
import com.davils.krypt.spiffe.fixture.member
import com.davils.krypt.spiffe.fixture.quoted
import com.davils.krypt.spiffe.fixture.read
import com.davils.krypt.spiffe.fixture.value
import com.davils.krypt.spiffe.fixture.x509Entry
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

private const val KEY_ID: String = "key-1"
private const val OTHER_KEY_ID: String = "key-2"
private const val SEQUENCE: Long = 12_035_488L
private const val HINT_SECONDS: Long = 2_419_200L
private const val LARGEST: Long = 9_007_199_254_740_991L
private const val DEPTH: Int = 40
private const val KID: String = "kid"
private const val X5C: String = "x5c"
private const val TWO: Int = 2
private const val BUNDLE: String = """{"keys":[]}"""
private const val ORG: String = """"example.org":"""

private val cnsa: Crypto = Crypto(
    environment {
        clock = FixedClock
        policy = CryptoPolicy.Cnsa2
    },
)

private fun sequenceOf(value: String): List<String> = listOf(member(name = "spiffe_sequence", value = value))

private fun hintOf(value: String): List<String> = listOf(member(name = "spiffe_refresh_hint", value = value))

private fun mapText(vararg members: String): String = """{"trust_domains":{""" + members.joinToString(",") + "}}"

class TrustBundlesTest : FunSpec({
    test("a bundle with both kinds of authority round-trips in the format of the specification") {
        val root = Authority.root(DOMAIN_ID)
        val signing = crypto.keys.generate(KeyType.P256).publicKey
        val rsa = crypto.keys.generate(KeyType.Rsa3072).publicKey
        val bundle = TrustBundle(
            trustDomain = domain,
            x509Authorities = listOf(root.certificate),
            jwtAuthorities = listOf(JwtAuthority(KEY_ID, signing), JwtAuthority(OTHER_KEY_ID, rsa)),
            sequence = SEQUENCE,
            refreshHint = HINT_SECONDS.seconds,
        )
        val text = codec.encode(bundle)
        text shouldContain X509_USE
        text shouldContain JWT_USE
        text shouldContain """"spiffe_sequence":$SEQUENCE"""
        text shouldContain """"spiffe_refresh_hint":$HINT_SECONDS"""
        text shouldContain chainOf(root.certificate)
        codec.read(text) shouldBe bundle
        val bare = TrustBundle(trustDomain = domain)
        codec.encode(bare) shouldBe BUNDLE
        codec.read(BUNDLE) shouldBe bare
        codec.read(BUNDLE).isEmpty shouldBe true
        codec.toString() shouldContain "TrustBundles"
    }

    test("the bundles of appendix A of the specification are read with their sequence and refresh hint") {
        val first = Authority.root(DOMAIN_ID)
        val second = Authority.root(DOMAIN_ID)
        val hint = hintOf("2419200")
        val initial = codec.read(bundleOf(x509Entry(first.certificate), extra = sequenceOf("1") + hint))
        initial.sequence shouldBe 1L
        initial.refreshHint shouldBe 28.days
        initial.x509Authorities shouldBe listOf(first.certificate)
        val rotated = bundleOf(
            x509Entry(first.certificate),
            x509Entry(second.certificate),
            extra = sequenceOf("2") + hint,
        )
        codec.read(rotated).x509Authorities shouldBe listOf(first.certificate, second.certificate)
    }

    test("keys of an unknown or missing use or type, and X.509 keys without certificates, are ignored") {
        val root = Authority.root(DOMAIN_ID)
        val jwk = jwkOf(root.certificate.publicKey ?: error("key"))
        val chain = chainOf(root.certificate)
        val ignored = listOf(
            entry(jwk, chain),
            entry(jwk, """"use":"wit-svid"""", chain),
            entry(jwk, """"use":"sig"""", chain),
            entry(jwk, """"use":1""", chain),
            entry(jwk, """"use":"X509-SVID"""", chain),
            entry(jwk, X509_USE),
            entry(jwk, X509_USE, member(name = X5C, value = array(emptyList()))),
            entry("""{"kty":"AKP","alg":"ML-DSA-44","pub":"AAAA"}""", X509_USE, chain),
            entry("""{"kty":"XYZ"}""", JWT_USE, member(name = KID, value = quoted(KEY_ID))),
            entry("""{"kty":"EC","crv":"P-192","x":"AA","y":"AA"}""", JWT_USE),
        )
        codec.read(bundleOf(ignored)).isEmpty shouldBe true
        val other = bundleOf(x509Entry(root.certificate), extra = listOf(member(name = "other", value = "{}")))
        codec.read(other).x509Authorities shouldBe listOf(root.certificate)
    }

    test("invalid keys of a known use refuse the whole bundle") {
        val root = Authority.root(DOMAIN_ID)
        val other = Authority.root(DOMAIN_ID)
        val pair = crypto.keys.generate(KeyType.P256)
        val jwk = jwkOf(root.certificate.publicKey ?: error("key"))
        val privateJwk = jsonWebKeys.of(key = pair.privateKey, keyId = KEY_ID)
        val secret = jsonWebKeys.of(key = crypto.keys.generateSecret(), keyId = KEY_ID)
        val publicJwk = jwkOf(pair.publicKey)
        val longKeyId = quoted("k".repeat(JwtAuthority.MAXIMUM_KEY_ID_LENGTH + 1))
        val cases = listOf(
            entry(jwk, X509_USE, chainOf(other.certificate)),
            entry(jwk, X509_USE, member(name = X5C, value = quoted("AAAA"))),
            entry(jwk, X509_USE, member(name = X5C, value = array(listOf(quoted("!!!"))))),
            entry("""{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}""", X509_USE, chainOf(root.certificate)),
            entry(privateJwk.encode(), JWT_USE),
            entry(secret.encode(), JWT_USE),
            entry(publicJwk, JWT_USE, member(name = KID, value = quoted(""))),
            entry(publicJwk, JWT_USE, member(name = KID, value = longKeyId)),
        )
        cases.forEach { case -> codec.failureOf(bundleOf(case)) shouldBe BundleFailure.InvalidKey }
        codec.failureOf(bundleOf(entry(publicJwk, JWT_USE))) shouldBe BundleFailure.MissingKeyId
        val twice = listOf(KEY_ID, KEY_ID).map { keyId -> entry(jwkOf(pair.publicKey, keyId), JWT_USE) }
        codec.failureOf(bundleOf(twice)) shouldBe BundleFailure.DuplicateKeyId
        val longest = entry(jwkOf(pair.publicKey, "k".repeat(JwtAuthority.MAXIMUM_KEY_ID_LENGTH)), JWT_USE)
        codec.read(bundleOf(longest)).jwtAuthorities.size shouldBe 1
    }

    test("keys the crypto policy refuses refuse the bundle") {
        val root = Authority.root(DOMAIN_ID)
        val strict = TrustBundles(cnsa)
        strict.failureOf(bundleOf(x509Entry(root.certificate))) shouldBe BundleFailure.InvalidKey
        val jwt = entry(jwkOf(crypto.keys.generate(KeyType.P256).publicKey, KEY_ID), JWT_USE)
        strict.failureOf(bundleOf(jwt)) shouldBe BundleFailure.InvalidKey
        val p384 = Authority.root(DOMAIN_ID, type = KeyType.P384)
        strict.read(bundleOf(x509Entry(p384.certificate))).x509Authorities shouldBe listOf(p384.certificate)
    }

    test("malformed bundles are refused") {
        val root = Authority.root(DOMAIN_ID)
        val good = x509Entry(root.certificate)
        val cases = listOf(
            "",
            "[]",
            "{",
            bundleOf(good).dropLast(1),
            "{}",
            """{"keys":{}}""",
            """{"keys":[1]}""",
            """{"keys":[],"keys":[]}""",
            bundleOf(good, extra = sequenceOf("-1")),
            bundleOf(good, extra = sequenceOf(quoted("1"))),
            bundleOf(good, extra = sequenceOf("1.5")),
            bundleOf(good, extra = hintOf("-1")),
            bundleOf(good, extra = hintOf("null")),
            bundleOf(good, extra = hintOf("4294967296")),
            bundleOf(good, extra = sequenceOf("9007199254740992")),
        )
        cases.forEach { case -> codec.failureOf(case) shouldBe BundleFailure.Malformed }
        val nested = "[".repeat(DEPTH) + "]".repeat(DEPTH)
        val deep = bundleOf(good, extra = listOf(member(name = "deep", value = nested)))
        codec.failureOf(deep) shouldBe BundleFailure.LimitExceeded
        codec.read(bundleOf(good, extra = sequenceOf("9007199254740991"))).sequence shouldBe LARGEST
        val longest = codec.read(bundleOf(good, extra = hintOf("4294967295")))
        longest.refreshHint shouldBe TrustBundle.MAXIMUM_REFRESH_HINT_SECONDS.seconds
    }

    test("a bundle is refused one byte or one key past its limits") {
        val root = Authority.root(DOMAIN_ID)
        val text = bundleOf(x509Entry(root.certificate), x509Entry(root.certificate))
        val sized = TrustBundles(crypto, SpiffeLimits(maximumBytes = text.length))
        sized.read(text).x509Authorities.size shouldBe TWO
        val small = TrustBundles(crypto, SpiffeLimits(maximumBytes = text.length - 1))
        small.failureOf(text) shouldBe BundleFailure.LimitExceeded
        val counted = TrustBundles(crypto, SpiffeLimits(maximumAuthorities = TWO))
        counted.read(text).x509Authorities.size shouldBe TWO
        val few = TrustBundles(crypto, SpiffeLimits(maximumAuthorities = 1))
        few.failureOf(text) shouldBe BundleFailure.LimitExceeded
    }

    test("a bundle map round-trips and names the trust domain of every bundle") {
        val root = Authority.root(DOMAIN_ID)
        val foreignRoot = Authority.root(FOREIGN_DOMAIN_ID)
        val signing = crypto.keys.generate(KeyType.P256).publicKey
        val own = TrustBundle(
            trustDomain = domain,
            x509Authorities = listOf(root.certificate),
            jwtAuthorities = listOf(JwtAuthority(KEY_ID, signing)),
            sequence = 1L,
        )
        val set = BundleSet(listOf(own, TrustBundle(foreign, listOf(foreignRoot.certificate))))
        val text = codec.encodeMap(set)
        text shouldContain """"trust_domains""""
        text shouldNotContain "spiffe_refresh_hint"
        codec.decodeMap(text).value() shouldBe set
        val empty = codec.encodeMap(BundleSet.Empty)
        codec.decodeMap(empty).value() shouldBe BundleSet.Empty
    }

    test("malformed bundle maps are refused") {
        val root = Authority.root(DOMAIN_ID)
        val bundle = bundleOf(x509Entry(root.certificate))
        val cases = listOf(
            "{}" to BundleFailure.Malformed,
            """{"trust_domains":[]}""" to BundleFailure.Malformed,
            mapText(ORG + "[]") to BundleFailure.Malformed,
            mapText(""""Example.org":$bundle""") to BundleFailure.InvalidTrustDomain,
            mapText(""""spiffe://example.org":$bundle""") to BundleFailure.InvalidTrustDomain,
            mapText(ORG + bundle, ORG + bundle) to BundleFailure.Malformed,
            mapText(ORG + """{"keys":[1]}""") to BundleFailure.Malformed,
        )
        cases.forEach { (text, failure) -> codec.decodeMap(text).failure() shouldBe failure }
        val two = mapText(ORG + bundle, """"example.com":$bundle""")
        val decoded = codec.decodeMap(two).value()
        decoded.size shouldBe TWO
        val narrow = TrustBundles(crypto, SpiffeLimits(maximumTrustDomains = 1))
        narrow.decodeMap(two).failure() shouldBe BundleFailure.LimitExceeded
        val tiny = TrustBundles(crypto, SpiffeLimits(maximumBytes = TWO))
        tiny.decodeMap(two).failure() shouldBe BundleFailure.LimitExceeded
    }
})
