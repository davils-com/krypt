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

package com.davils.krypt.acme.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.acme.AcmeError
import com.davils.krypt.acme.AcmeFailure
import com.davils.krypt.acme.fixture.Vectors
import com.davils.krypt.acme.fixture.failure
import com.davils.krypt.acme.fixture.value
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jws.JwsAlgorithm
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private const val MAXIMUM_URL: Int = 40
private const val MINUTE: Long = 60L
private const val TAB: Char = '\t'
private const val PLAIN: String = "http://a.test/"
private const val RFC9110_DATE: String = "Sun, 06 Nov 1994 08:49:37 GMT"
private const val RFC9110_SECONDS: Long = 784_111_777L
private const val ALTERNATE: String = "alternate"
private const val FIRST: String = "https://a.test/1"
private const val SECOND: String = "https://a.test/2"
private const val LABEL_LIMIT: Int = 63
private const val SHORT_LABEL: Int = 50
private const val LABELS: Int = 4
private const val NONCE_LIMIT: Int = 512

private fun url(text: String, isHttpAllowed: Boolean = false): Outcome<String, AcmeFailure> =
    reading { Urls.checked(text = text, isHttpAllowed = isHttpAllowed, maximumLength = MAXIMUM_URL) }

private fun date(text: String) = reading { HttpDates.parse(text) }

private fun wait(text: String, now: Instant = Instant.fromEpochSeconds(RFC9110_SECONDS)) =
    reading { HttpDates.retryAfter(value = text, now = now, maximum = 1.days) }

private fun links(vararg values: String, maximum: Int = 4) =
    reading { Links.parse(values = values.toList(), maximum = maximum) }

private val everyValue: List<JsonValue> = listOf(
    JsonValue.Text("t"),
    JsonValue.Integer(1),
    JsonValue.Bool(true),
    JsonValue.Null,
    JsonValue.Array(emptyList()),
    JsonValue.Object.Empty,
)

class ParsersTest : FunSpec({
    test("accepts absolute https URLs and refuses everything else") {
        url("https://a.test/x?y=1").value() shouldBe "https://a.test/x?y=1"
        url("https://a.test").value() shouldBe "https://a.test"
        url(PLAIN).failure() shouldBe AcmeError.InsecureUrl
        url(text = PLAIN, isHttpAllowed = true).value() shouldBe PLAIN
        url(text = "ftp://a.test/", isHttpAllowed = true).failure() shouldBe AcmeError.InsecureUrl
        url("/relative").failure() shouldBe AcmeError.InsecureUrl
        url("HTTPS://a.test/").failure() shouldBe AcmeError.InsecureUrl
        val malformed = listOf(
            "https://",
            "https:///x",
            "https://u@a.test/",
            "https://a.test/#f",
            "https://a.test/ x",
            "https://a.é",
        )
        malformed.forEach { text -> url(text).failure() shouldBe AcmeError.Malformed }
        url("https://a.test/" + "x".repeat(MAXIMUM_URL)).failure() shouldBe AcmeError.LimitExceeded
    }

    test("reads the HTTP date of RFC 9110 and checks every field") {
        date(RFC9110_DATE).value() shouldBe Instant.fromEpochSeconds(RFC9110_SECONDS)
        date("Tue, 29 Feb 2000 00:00:00 GMT").value() shouldBe Instant.parse("2000-02-29T00:00:00Z")
        date("Sun, 29 Feb 2004 00:00:00 GMT").value() shouldBe Instant.parse("2004-02-29T00:00:00Z")
        date("Sat, 01 Jan 0000 00:00:00 GMT").value() shouldBe Instant.parse("0000-01-01T00:00:00Z")
        date("Fri, 31 Dec 9999 23:59:59 GMT").value() shouldBe Instant.parse("9999-12-31T23:59:59Z")
        listOf(
            "Mon, 06 Nov 1994 08:49:37 GMT",
            "Sun, 06 Xyz 1994 08:49:37 GMT",
            "Sun, 31 Nov 1994 08:49:37 GMT",
            "Thu, 29 Feb 1900 00:00:00 GMT",
            "Sun, 00 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:49:37 GMT",
            "Sun, 06 Nov 1994 08:60:37 GMT",
            "Sun, 06 Nov 1994 08:49:60 GMT",
            "Sun, 0x Nov 1994 08:49:37 GMT",
            "Sun, -6 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 gmt",
            "Sun, 06 Nov 1994 08:49:37 GMT ",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "",
        ).forEach { text -> date(text).failure() shouldBe AcmeError.Malformed }
    }

    test("reads Retry-After as seconds or as a date, bounded") {
        wait("120").value() shouldBe 120.seconds
        wait(" 0\t").value() shouldBe Duration.ZERO
        wait("86400").value() shouldBe 1.days
        wait("86401").failure() shouldBe AcmeError.LimitExceeded
        wait("12345678901").failure() shouldBe AcmeError.LimitExceeded
        wait(RFC9110_DATE).value() shouldBe Duration.ZERO
        val minuteBefore = Instant.fromEpochSeconds(RFC9110_SECONDS - MINUTE)
        wait(text = RFC9110_DATE, now = minuteBefore).value() shouldBe MINUTE.seconds
        wait(text = RFC9110_DATE, now = Instant.fromEpochSeconds(0)).failure() shouldBe AcmeError.LimitExceeded
        wait("-1").failure() shouldBe AcmeError.Malformed
        wait("").failure() shouldBe AcmeError.Malformed
    }

    test("reads Link fields of RFC 8288") {
        links("""<$FIRST>;rel="$ALTERNATE"""").value() shouldContainExactly
            listOf(Link(target = FIRST, relations = listOf(ALTERNATE)))
        val first = """<$FIRST>$TAB; REL = Alternate , <$SECOND>;rel="index  up";title="a \"b\"","""
        links(first, "<$FIRST>").value() shouldContainExactly
            listOf(
                Link(target = FIRST, relations = listOf(ALTERNATE)),
                Link(target = SECOND, relations = listOf("index", "up")),
                Link(target = FIRST, relations = emptyList()),
            )
        links("").value() shouldBe emptyList()
        val broken = listOf(
            "$FIRST;rel=x",
            "<$FIRST",
            "<$FIRST>;rel",
            "<$FIRST>;=x",
            """<$FIRST>;rel="x""",
            "<$FIRST> x",
            "<$FIRST>;rel=",
            "<$FIRST>;rel;x",
            "<$FIRST>;rel=\u00E9",
        )
        broken.forEach { text -> links(text).failure() shouldBe AcmeError.Malformed }
        links("<$FIRST>, <$SECOND>", maximum = 1).failure() shouldBe AcmeError.LimitExceeded
    }

    test("checks DNS names, tokens, nonces and certificate identifiers") {
        listOf("a.b", "*.a.b", "xn--abc.de", "A-1.b", "localhost", "a".repeat(LABEL_LIMIT) + ".b")
            .forEach { name -> DnsNames.isValid(name) shouldBe true }
        listOf("", "*.", "-a.b", "a-.b", "a..b", "a_b.c", "*.*.a", "a.b.", "a".repeat(LABEL_LIMIT + 1) + ".b", "a{.b")
            .forEach { name -> DnsNames.isValid(name) shouldBe false }
        listOf("a`.b", "a@.b", "a/.b", "a:.b", "a[.b")
            .forEach { name -> DnsNames.isValid(name) shouldBe false }
        val label = "a".repeat(SHORT_LABEL) + "."
        DnsNames.isValid(label.repeat(LABELS) + "a".repeat(SHORT_LABEL - 1)) shouldBe true
        DnsNames.isValid(label.repeat(LABELS + 1) + "abc") shouldBe false
        Tokens.isNonce("abc_-XYZ09") shouldBe true
        Tokens.isNonce("") shouldBe false
        listOf("a+b", "a{", "a`", "a@", "a/", "a:", "a[").forEach { nonce -> Tokens.isNonce(nonce) shouldBe false }
        Tokens.isNonce("a".repeat(NONCE_LIMIT + 1)) shouldBe false
        Tokens.isCertificateId(Vectors.RFC9773_IDENTIFIER) shouldBe true
        listOf("a", "a.b.c", ".b", "a.", "a+.b", "a." + "b".repeat(NONCE_LIMIT))
            .forEach { text -> Tokens.isCertificateId(text) shouldBe false }
    }

    test("fits JWS algorithms to keys and picks defaults") {
        SigningAlgorithms.defaultFor(family = KeyFamily.Rsa, curve = null) shouldBe JwsAlgorithm.RS256
        SigningAlgorithms.defaultFor(family = KeyFamily.Ed25519, curve = null) shouldBe JwsAlgorithm.EdDSA
        SigningAlgorithms.defaultFor(family = KeyFamily.Ed448, curve = null) shouldBe JwsAlgorithm.EdDSA
        SigningAlgorithms.defaultFor(family = KeyFamily.Ec, curve = EllipticCurve.P256) shouldBe JwsAlgorithm.ES256
        SigningAlgorithms.defaultFor(family = KeyFamily.Ec, curve = EllipticCurve.P384) shouldBe JwsAlgorithm.ES384
        SigningAlgorithms.defaultFor(family = KeyFamily.Ec, curve = EllipticCurve.P521) shouldBe JwsAlgorithm.ES512
        SigningAlgorithms.defaultFor(family = KeyFamily.Ec, curve = null) shouldBe null
        SigningAlgorithms.defaultFor(family = KeyFamily.X25519, curve = null) shouldBe null
        SigningAlgorithms.defaultFor(family = KeyFamily.MlDsa, curve = EllipticCurve.P256) shouldBe null
    }

    test("reads JSON members by their types") {
        val json = JsonValue.Object.of(
            "t" to JsonValue.Text("x"),
            "a" to JsonValue.Array(listOf(JsonValue.Text("1"), JsonValue.Text("2"))),
        )
        everyValue.forEach { value ->
            reading { value.asText() }.isSuccess() shouldBe (value is JsonValue.Text)
            reading { value.asObject() }.isSuccess() shouldBe (value is JsonValue.Object)
            reading { value.asItems() }.isSuccess() shouldBe (value is JsonValue.Array)
            reading { value.asBoolean() }.isSuccess() shouldBe (value is JsonValue.Bool)
            reading { value.asInteger() }.isSuccess() shouldBe (value is JsonValue.Integer)
        }
        reading { json.requiredText("t") }.value() shouldBe "x"
        reading { json.requiredText("missing") }.failure() shouldBe AcmeError.Malformed
        reading { json.texts(name = "a", maximum = 2) }.value() shouldContainExactly listOf("1", "2")
        reading { json.texts(name = "a", maximum = 1) }.failure() shouldBe AcmeError.LimitExceeded
        reading { json.texts(name = "missing", maximum = 1) }.failure() shouldBe null
        reading { require(false) }.failure() shouldBe AcmeError.Malformed
        supported("x").value() shouldBe "x"
        supported<String>(null).failure() shouldBe AcmeError.Unsupported
        reading { Utf8.decode(Vectors.hex("c328")) }.failure() shouldBe AcmeError.Malformed
        reading { Utf8.decode(Vectors.hex("c3a9")) }.value() shouldBe "é"
    }

    test("keeps a bounded pool of nonces, newest first") {
        val pool = NoncePool(2)
        pool.take() shouldBe null
        listOf("a", "b", "c").forEach { nonce -> pool.offer(nonce) }
        pool.size() shouldBe 2
        pool.take() shouldBe "c"
        pool.take() shouldBe "b"
        pool.take() shouldBe null
    }
})

private fun Outcome<*, *>.isSuccess(): Boolean = this is Outcome.Success
