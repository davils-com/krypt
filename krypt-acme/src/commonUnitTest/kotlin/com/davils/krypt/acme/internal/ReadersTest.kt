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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.acme.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.acme.AcmeError
import com.davils.krypt.acme.AcmeFailure
import com.davils.krypt.acme.AcmeIdentifier
import com.davils.krypt.acme.AcmeLimits
import com.davils.krypt.acme.AcmeProblemType
import com.davils.krypt.acme.AcmeStatus
import com.davils.krypt.acme.fixture.Vectors
import com.davils.krypt.acme.fixture.crypto
import com.davils.krypt.acme.fixture.failure
import com.davils.krypt.acme.fixture.signer
import com.davils.krypt.acme.fixture.value
import com.davils.krypt.acme.order.ChallengeType
import com.davils.krypt.acme.order.Challenges
import com.davils.krypt.asn1.pem.Pem
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.StrictJson
import com.davils.krypt.x509.Certificates
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private const val URL: String = "https://ca.test/x"
private const val TIME: String = "2027-01-15T10:00:00Z"
private const val TOKEN: String = Vectors.RFC8555_TOKEN
private const val DNS: String = """{"type":"dns","value":"a.b"}"""
private const val LONG_TIME: Int = 65
private const val FORBIDDEN: Int = 403
private val BROKEN_PEM: String =
    listOf("-----BEGIN CERTIFICATE-----", "!!!!", "-----END CERTIFICATE-----").joinToString(separator = "\n")
private val certificates = Certificates(crypto)
private val readers = Readers(
    limits = AcmeLimits(maximumEntries = 2, maximumCertificates = 2),
    isHttpAllowed = false,
    certificates = certificates,
)

private fun obj(vararg parts: String): JsonValue.Object =
    checkNotNull(StrictJson.decodeObject(parts.joinToString(separator = "").encodeToByteString()).getOrNull())

private fun <T> read(vararg parts: String, block: Readers.(JsonValue.Object) -> T): Outcome<T, AcmeFailure> =
    reading { readers.block(obj(*parts)) }

private fun challenge(type: String = "http-01", token: String = TOKEN): String =
    """{"type":"$type","url":"$URL","status":"pending","token":"$token"}"""

class ReadersTest : FunSpec({
    test("reads a directory with and without its optional members") {
        val full = read(
            """{"newNonce":"$URL/1","newAccount":"$URL/2","newOrder":"$URL/3","newAuthz":"$URL/4",""",
            """"revokeCert":"$URL/5","keyChange":"$URL/6","renewalInfo":"$URL/7","unknown":1,"meta":{""",
            """"termsOfService":"$URL/8","website":"$URL/9","caaIdentities":["a","b"],""",
            """"externalAccountRequired":true,"profiles":{}}}""",
        ) { json -> directory(json) }.value()
        full.newAuthorization shouldBe "$URL/4"
        full.renewalInfo shouldBe "$URL/7"
        full.meta.website shouldBe "$URL/9"
        full.meta.isExternalAccountRequired shouldBe true
        val minimal = read("""{"newNonce":"$URL","newAccount":"$URL","newOrder":"$URL"}""") { json ->
            directory(json)
        }.value()
        minimal.keyChange shouldBe null
        minimal.meta.caaIdentities shouldBe emptyList()
        minimal.meta.isExternalAccountRequired shouldBe false
        read("""{"newNonce":"$URL","newAccount":"$URL"}""") { json -> directory(json) }.failure() shouldBe
            AcmeError.Malformed
        read("""{"newNonce":"http://ca.test","newAccount":"$URL","newOrder":"$URL"}""") { json ->
            directory(json)
        }.failure() shouldBe AcmeError.InsecureUrl
        val crowded = listOf(
            """{"newNonce":"$URL","newAccount":"$URL","newOrder":"$URL",""",
            """"meta":{"caaIdentities":["a","b","c"]}}""",
        ).joinToString(separator = "")
        read(crowded) { json -> directory(json) }.failure() shouldBe AcmeError.LimitExceeded
        read("""{"newNonce":"$URL","newAccount":"$URL","newOrder":"$URL","meta":[]}""") { json -> directory(json) }
            .failure() shouldBe AcmeError.Malformed
    }

    test("reads accounts and refuses bad statuses and lists") {
        val text = """{"status":"valid","contact":["mailto:a@b.c"],"termsOfServiceAgreed":true,"orders":"$URL"}"""
        val account = read(text) { json -> account(json = json, url = URL, isCreated = true) }.value()
        account.orders shouldBe URL
        account.isTermsOfServiceAgreed shouldBe true
        val minimal = read("""{"status":"revoked"}""") { json -> account(json = json, url = URL, isCreated = false) }
            .value()
        minimal.contacts shouldBe emptyList()
        minimal.isTermsOfServiceAgreed shouldBe null
        listOf(
            """{"status":"pending"}""",
            """{"status":"unknown"}""",
            """{}""",
            """{"status":1}""",
            """{"status":"valid","contact":"mailto:a@b.c"}""",
            """{"status":"valid","termsOfServiceAgreed":"yes"}""",
        ).forEach { text ->
            val outcome = read(text) { json -> account(json = json, url = URL, isCreated = false) }
            outcome.failure() shouldBe AcmeError.Malformed
        }
        val crowded = read("""{"status":"valid","contact":["a","b","c"]}""") { json ->
            account(json = json, url = URL, isCreated = false)
        }
        crowded.failure() shouldBe AcmeError.LimitExceeded
    }

    test("reads orders with every member and refuses broken ones") {
        val order = read(
            """{"status":"invalid","expires":"$TIME","identifiers":[{"type":"dns","value":"a.example"},""",
            """{"type":"ip","value":"2001:db8::1"}],"notBefore":"$TIME","notAfter":"$TIME",""",
            """"authorizations":["$URL/a"],"finalize":"$URL/f","certificate":"$URL/c",""",
            """"replaces":"${Vectors.RFC9773_IDENTIFIER}","error":{"type":"urn:ietf:params:acme:error:caa",""",
            """"subproblems":[{"type":"x"}]}}""",
        ) { json -> order(json = json, url = URL, retryAfter = 1.seconds) }.value()
        order.status shouldBe AcmeStatus.Invalid
        order.identifiers shouldContainExactly
            listOf(AcmeIdentifier.dns("a.example"), AcmeIdentifier.ip("2001:db8::1"))
        order.expires shouldBe Instant.parse(TIME)
        order.notAfter shouldBe Instant.parse(TIME)
        order.certificate shouldBe "$URL/c"
        order.error.shouldNotBeNull().kind shouldBe AcmeProblemType.Caa
        order.error.subproblems shouldBe emptyList()
        order.retryAfter shouldBe 1.seconds
        val base = """"status":"pending","authorizations":[],"finalize":"$URL""""
        listOf(
            """{$base,"identifiers":[]}""",
            """{$base}""",
            """{$base,"identifiers":[{"type":"email","value":"a@b.c"}]}""",
            """{$base,"identifiers":[{"type":"dns","value":"a_b.c"}]}""",
            """{$base,"identifiers":["a.example"]}""",
            """{$base,"identifiers":[$DNS],"replaces":"nope"}""",
            """{$base,"identifiers":[$DNS],"expires":"yesterday"}""",
            """{$base,"identifiers":[$DNS],"expires":"${"9".repeat(LONG_TIME)}"}""",
            """{"status":"deactivated","authorizations":[],"finalize":"$URL","identifiers":[$DNS]}""",
            """{"status":"pending","finalize":"$URL","identifiers":[$DNS]}""",
        ).forEach { text ->
            val outcome = read(text) { json -> order(json = json, url = URL, retryAfter = null) }
            outcome.failure() shouldBe AcmeError.Malformed
        }
    }

    test("reads authorizations and their challenges") {
        val authorization = read(
            """{"identifier":{"type":"dns","value":"example.org"},"status":"pending","wildcard":true,""",
            """"expires":"$TIME","challenges":[${challenge()},{"type":"x-01","url":"$URL","status":"valid",""",
            """"validated":"$TIME","error":{"type":"urn:ietf:params:acme:error:dns"}}]}""",
        ) { json -> authorization(json = json, url = URL, retryAfter = null) }.value()
        authorization.isWildcard shouldBe true
        authorization.challenges shouldHaveSize 2
        authorization.challenge(ChallengeType.Http01).shouldNotBeNull().token shouldBe TOKEN
        authorization.challenge(ChallengeType.Dns01) shouldBe null
        val unknown = authorization.challenges.last()
        unknown.kind shouldBe null
        unknown.token shouldBe null
        unknown.validated shouldBe Instant.parse(TIME)
        unknown.error.shouldNotBeNull().kind shouldBe AcmeProblemType.Dns
        val identifier = """"identifier":{"type":"dns","value":"example.org"},"status":"pending""""
        listOf(
            """{$identifier,"challenges":[${challenge(token = "short")}]}""",
            """{$identifier,"challenges":[{"type":"dns-01","url":"$URL","status":"pending"}]}""",
            """{"identifier":{"type":"dns","value":"a.b"},"status":"processing","challenges":[${challenge()}]}""",
            """{"status":"pending","challenges":[]}""",
            """{$identifier}""",
        ).forEach { text ->
            read(text) { json -> authorization(json = json, url = URL, retryAfter = null) }.failure() shouldBe
                AcmeError.Malformed
        }
        read("""{$identifier,"challenges":[${challenge()},${challenge()},${challenge()}]}""") { json ->
            authorization(json = json, url = URL, retryAfter = null)
        }.failure() shouldBe AcmeError.LimitExceeded
    }

    test("reads problem documents of RFC 9457 with subproblems") {
        val problem = read(
            """{"type":"urn:ietf:params:acme:error:compound","title":"t","detail":"d","status":403,""",
            """"instance":"$URL","subproblems":[{"type":"urn:ietf:params:acme:error:rejectedIdentifier",""",
            """"identifier":{"type":"dns","value":"a.example"},"subproblems":[{}]},{}]}""",
        ) { json -> problem(json = json, retryAfter = 2.seconds) }.value()
        problem.kind shouldBe AcmeProblemType.Compound
        problem.title shouldBe "t"
        problem.status shouldBe FORBIDDEN
        problem.instance shouldBe URL
        problem.retryAfter shouldBe 2.seconds
        problem.subproblems shouldHaveSize 2
        problem.subproblems.first().identifier shouldBe AcmeIdentifier.dns("a.example")
        problem.subproblems.last().type shouldBe "about:blank"
        problem.subproblems.last().kind shouldBe null
        val broken = listOf("""{"status":99}""", """{"status":600}""", """{"type":7}""", """{"subproblems":[1]}""")
        broken.forEach { text ->
            read(text) { json -> problem(json = json, retryAfter = null) }.failure() shouldBe AcmeError.Malformed
        }
        read("""{"subproblems":[{},{},{}]}""") { json -> problem(json = json, retryAfter = null) }.failure() shouldBe
            AcmeError.LimitExceeded
    }

    test("reads renewal information of RFC 9773") {
        val info = read(
            """{"suggestedWindow":{"start":"2027-01-01T00:00:00Z","end":"2027-01-02T00:00:00Z"},""",
            """"explanationURL":"$URL"}""",
        ) { json -> renewal(json = json, certificateId = "a.b", retryAfter = null) }.value()
        info.explanation shouldBe URL
        info.isRenewalDue(Instant.parse("2026-12-31T00:00:00Z")) shouldBe false
        listOf(
            """{"suggestedWindow":{"start":"$TIME","end":"$TIME"}}""",
            """{"suggestedWindow":{"start":"$TIME"}}""",
            """{}""",
        ).forEach { text ->
            read(text) { json -> renewal(json = json, certificateId = "a.b", retryAfter = null) }.failure() shouldBe
                AcmeError.Malformed
        }
    }

    test("reads certificate chains in PEM and refuses everything else") {
        val leaf = Challenges(crypto).tlsAlpn01Certificate(
            identifier = AcmeIdentifier.dns("example.org"),
            keyAuthorization = Vectors.KEY_AUTHORIZATION,
            signer = signer(),
        )
        val pem = certificates.encodePem(leaf)
        val links = listOf(
            Link(target = "$URL/alt", relations = listOf("alternate")),
            Link(target = "/relative", relations = listOf("index")),
        )
        val chain = reading { readers.chain(body = (pem + pem).encodeToByteString(), links = links) }.value()
        chain.certificates shouldContainExactly listOf(leaf, leaf)
        chain.alternates shouldContainExactly listOf("$URL/alt")
        val insecure = listOf(Link(target = "http://ca.test/alt", relations = listOf("alternate")))
        reading { readers.chain(body = pem.encodeToByteString(), links = insecure) }.failure() shouldBe
            AcmeError.InsecureUrl
        val long = (pem + pem + pem).encodeToByteString()
        reading { readers.chain(body = long, links = emptyList()) }.failure() shouldBe AcmeError.LimitExceeded
        val broken = listOf(
            ByteString(),
            "not pem".encodeToByteString(),
            BROKEN_PEM.encodeToByteString(),
            Pem.encode(label = "PRIVATE KEY", bytes = leaf.encoded).encodeToByteString(),
            Pem.encode(label = "CERTIFICATE", bytes = Vectors.hex("3000")).encodeToByteString(),
            Vectors.hex("ff"),
        )
        broken.forEach { body ->
            reading { readers.chain(body = body, links = emptyList()) }.failure() shouldBe AcmeError.Malformed
        }
    }
})
