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

package com.davils.krypt.spiffe

import com.davils.krypt.spiffe.fixture.DOMAIN
import com.davils.krypt.spiffe.fixture.DOMAIN_ID
import com.davils.krypt.spiffe.fixture.FOREIGN_WORKLOAD
import com.davils.krypt.spiffe.fixture.WORKLOAD
import com.davils.krypt.spiffe.fixture.domain
import com.davils.krypt.spiffe.fixture.failure
import com.davils.krypt.spiffe.fixture.foreign
import com.davils.krypt.spiffe.fixture.value
import com.davils.krypt.spiffe.fixture.workload
import com.davils.krypt.x509.name.GeneralName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain

private const val PREFIX: String = "spiffe://"
private const val ASCII: Int = 128
private const val ID_HEAD: Int = 9
private const val SEGMENT: String = "segment"

private val SPEC_EXAMPLES: List<Triple<String, String, List<String>>> = listOf(
    Triple(
        first = "spiffe://staging.example.com/payments/mysql",
        second = "staging.example.com",
        third = listOf("payments", "mysql"),
    ),
    Triple(
        first = "spiffe://staging.example.com/payments/web-fe",
        second = "staging.example.com",
        third = listOf("payments", "web-fe"),
    ),
    Triple(
        first = "spiffe://k8s-west.example.com/ns/staging/sa/default",
        second = "k8s-west.example.com",
        third = listOf("ns", "staging", "sa", "default"),
    ),
    Triple(
        first = "spiffe://example.com/9eebccd2-12bf-40a6-b262-65fe0487d453",
        second = "example.com",
        third = listOf("9eebccd2-12bf-40a6-b262-65fe0487d453"),
    ),
    Triple(
        first = "spiffe://trust_domain_name.example.com",
        second = "trust_domain_name.example.com",
        third = emptyList(),
    ),
    Triple(
        first = "spiffe://192.168.1.1/a.b/C_d",
        second = "192.168.1.1",
        third = listOf("a.b", "C_d"),
    ),
)

private fun isDomainCharacter(char: Char): Boolean =
    char in 'a'..'z' || char in '0'..'9' || char == '.' || char == '-' || char == '_'

private fun isPathCharacter(char: Char): Boolean = isDomainCharacter(char) || char in 'A'..'Z'

private val DOMAIN_SPECIALS: Map<Char, SpiffeIdFailure> = mapOf(
    '%' to SpiffeIdFailure.PercentEncoded,
    '@' to SpiffeIdFailure.UserInfo,
    ':' to SpiffeIdFailure.Port,
    '?' to SpiffeIdFailure.Query,
    '#' to SpiffeIdFailure.Fragment,
)

private val PATH_SPECIALS: Map<Char, SpiffeIdFailure> = mapOf(
    '%' to SpiffeIdFailure.PercentEncoded,
    '?' to SpiffeIdFailure.Query,
    '#' to SpiffeIdFailure.Fragment,
)

private fun domainFailureOf(char: Char): SpiffeIdFailure? =
    DOMAIN_SPECIALS[char] ?: SpiffeIdFailure.BadTrustDomainCharacter.takeUnless { isDomainCharacter(char) }

private fun pathFailureOf(char: Char): SpiffeIdFailure? =
    PATH_SPECIALS[char] ?: SpiffeIdFailure.BadPathCharacter.takeUnless { isPathCharacter(char) }

private val CHARACTERS: List<Char> = (0 until ASCII).map { code -> code.toChar() }.filter { char -> char != '/' } +
    listOf('é', 'İ', 'K', '．')

class SpiffeIdTest : FunSpec({
    test("the examples of the SPIFFE ID specification parse into their trust domain and segments") {
        SPEC_EXAMPLES.forEach { (text, name, segments) ->
            val id = SpiffeId.parse(text).value()
            id.text shouldBe text
            id.toString() shouldBe text
            id.trustDomain.name shouldBe name
            id.segments shouldBe segments
            id.isTrustDomainId shouldBe segments.isEmpty()
            SpiffeId.of(id.trustDomain, segments) shouldBe id
        }
    }

    test("every character of a trust domain name is checked") {
        CHARACTERS.forEach { char ->
            val expected = domainFailureOf(char)
            SpiffeId.parse("${PREFIX}a${char}b/x").failure() shouldBe expected
            TrustDomain.parse("a${char}b").failure() shouldBe expected
        }
    }

    test("every character of a path segment is checked") {
        CHARACTERS.forEach { char ->
            SpiffeId.parse("${PREFIX}example.org/a${char}b").failure() shouldBe pathFailureOf(char)
        }
    }

    test("forbidden forms are refused") {
        val cases = listOf(
            "" to SpiffeIdFailure.Empty,
            "http://example.org/a" to SpiffeIdFailure.WrongScheme,
            "SPIFFE://example.org/a" to SpiffeIdFailure.WrongScheme,
            "spiffe:/example.org/a" to SpiffeIdFailure.WrongScheme,
            "spiffe:example.org" to SpiffeIdFailure.WrongScheme,
            " spiffe://example.org" to SpiffeIdFailure.WrongScheme,
            "spiffe://" to SpiffeIdFailure.MissingTrustDomain,
            "spiffe:///a" to SpiffeIdFailure.MissingTrustDomain,
            "spiffe://Example.org/a" to SpiffeIdFailure.BadTrustDomainCharacter,
            "spiffe://[::1]/a" to SpiffeIdFailure.BadTrustDomainCharacter,
            "spiffe://user@example.org/a" to SpiffeIdFailure.UserInfo,
            "spiffe://example.org:8443/a" to SpiffeIdFailure.Port,
            "spiffe://example.org?q" to SpiffeIdFailure.Query,
            "spiffe://example.org#f" to SpiffeIdFailure.Fragment,
            "spiffe://example.org/a?q=1" to SpiffeIdFailure.Query,
            "spiffe://example.org/a#f" to SpiffeIdFailure.Fragment,
            "spiffe://example.org/a%2Fb" to SpiffeIdFailure.PercentEncoded,
            "spiffe://ex%41mple.org/a" to SpiffeIdFailure.PercentEncoded,
            "spiffe://example.org/" to SpiffeIdFailure.TrailingSlash,
            "spiffe://example.org/a/" to SpiffeIdFailure.TrailingSlash,
            "spiffe://example.org//a" to SpiffeIdFailure.EmptySegment,
            "spiffe://example.org/a//b" to SpiffeIdFailure.EmptySegment,
            "spiffe://example.org/." to SpiffeIdFailure.DotSegment,
            "spiffe://example.org/a/../b" to SpiffeIdFailure.DotSegment,
            "spiffe://example.org/a/./b" to SpiffeIdFailure.DotSegment,
            "spiffe://example.org/a b" to SpiffeIdFailure.BadPathCharacter,
            "spiffe://example.org/a\\b" to SpiffeIdFailure.BadPathCharacter,
        )
        cases.forEach { (text, failure) -> SpiffeId.parse(text).failure() shouldBe failure }
        SpiffeId.parse("spiffe://example.org/...").value().segments shouldBe listOf("...")
    }

    test("an id and a trust domain name are refused one character past their limits") {
        val name = "a".repeat(TrustDomain.MAXIMUM_LENGTH)
        TrustDomain.parse(name).value().name shouldBe name
        TrustDomain.parse(name + "a").failure() shouldBe SpiffeIdFailure.TrustDomainTooLong
        TrustDomain.parse("").failure() shouldBe SpiffeIdFailure.MissingTrustDomain
        SpiffeId.parse(PREFIX + name + "a").failure() shouldBe SpiffeIdFailure.TrustDomainTooLong
        val fill = SpiffeId.MAXIMUM_LENGTH - ID_HEAD - TrustDomain.MAXIMUM_LENGTH - 1
        val longest = PREFIX + name + "/" + "b".repeat(fill)
        val parsed = SpiffeId.parse(longest).value()
        parsed.text.length shouldBe SpiffeId.MAXIMUM_LENGTH
        SpiffeId.parse(longest + "b").failure() shouldBe SpiffeIdFailure.TooLong
        val trustDomain = TrustDomain.of(name)
        trustDomain.idOf("b".repeat(fill)).text shouldBe longest
        shouldThrow<IllegalArgumentException> { trustDomain.idOf("b".repeat(fill + 1)) }
    }

    test("ids are built from segments, which are checked") {
        domain.idOf("ns", "prod", "sa", "api") shouldBe workload
        domain.id.text shouldBe DOMAIN_ID
        domain.id.isTrustDomainId shouldBe true
        SpiffeId.of(domain, emptyList()) shouldBe domain.id
        listOf("", ".", "..", "a/b", "a%20", "a b").forEach { segment ->
            shouldThrow<IllegalArgumentException> { domain.idOf(SEGMENT, segment) }
        }
        shouldThrow<IllegalArgumentException> { TrustDomain.of("Example.org") }.message shouldContain "Example.org"
    }

    test("an id is read from a URI name and written as one") {
        SpiffeId.of(GeneralName.Uri(WORKLOAD)).value() shouldBe workload
        SpiffeId.of(GeneralName.Dns(DOMAIN)).failure() shouldBe SpiffeIdFailure.WrongScheme
        SpiffeId.of(GeneralName.Uri("https://example.org/")).failure() shouldBe SpiffeIdFailure.WrongScheme
        workload.toGeneralName() shouldBe GeneralName.Uri(WORKLOAD)
    }

    test("membership compares the trust domain only") {
        workload.memberOf(domain) shouldBe true
        workload.memberOf(foreign) shouldBe false
        val foreignId = SpiffeId.parse(FOREIGN_WORKLOAD).value()
        foreignId.memberOf(foreign) shouldBe true
        val evil = SpiffeId.parse("spiffe://example.org.evil/ns/prod/sa/api").value()
        evil.memberOf(domain) shouldBe false
    }

    test("ids and trust domains compare by their text, and the path with regard to case") {
        val upper = SpiffeId.parse("spiffe://example.org/NS/prod/sa/api").value()
        upper shouldNotBe workload
        val same = SpiffeId.parse(WORKLOAD).value()
        workload shouldBe same
        workload.hashCode() shouldBe same.hashCode()
        workload.equals(WORKLOAD) shouldBe false
        (upper < workload) shouldBe true
        workload.compareTo(same) shouldBe 0
        domain shouldBe TrustDomain.of(DOMAIN)
        domain shouldNotBe foreign
        domain.equals(DOMAIN) shouldBe false
        domain.hashCode() shouldBe TrustDomain.of(DOMAIN).hashCode()
        domain.toString() shouldBe DOMAIN
        (foreign < domain) shouldBe true
        listOf(domain, foreign).sorted() shouldBe listOf(foreign, domain)
    }
})
