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

package com.davils.krypt.acme

import com.davils.krypt.acme.account.AccountKey
import com.davils.krypt.acme.account.AcmeAccount
import com.davils.krypt.acme.account.ExternalAccountBinding
import com.davils.krypt.acme.fixture.Vectors
import com.davils.krypt.acme.fixture.accountKey
import com.davils.krypt.acme.fixture.crypto
import com.davils.krypt.acme.fixture.signer
import com.davils.krypt.acme.internal.OrderTimes
import com.davils.krypt.acme.order.AcmeAuthorization
import com.davils.krypt.acme.order.AcmeChallenge
import com.davils.krypt.acme.order.AcmeOrder
import com.davils.krypt.acme.order.CertificateChain
import com.davils.krypt.acme.order.ChallengeType
import com.davils.krypt.acme.order.Challenges
import com.davils.krypt.acme.renewal.RenewalInfo
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.x509.Certificate
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private const val URL: String = "https://ca.test/x"
private const val OTHER: String = "https://ca.test/y"
private const val MAC_BYTES: Int = 32
private val TIME: Instant = Instant.fromEpochSeconds(1_800_000_000L)

private fun <T : Any> checkValue(value: T, same: T, others: List<T>) {
    value shouldBe same
    value.hashCode() shouldBe same.hashCode()
    value.equals("other") shouldBe false
    others.forEach { other -> value shouldNotBe other }
}

private fun problem(type: String = "urn:ietf:params:acme:error:dns", detail: String? = "d") = AcmeProblem(
    type = type,
    kind = AcmeProblemType.of(type),
    title = null,
    detail = detail,
    status = null,
    instance = null,
    identifier = null,
    subproblems = emptyList(),
    retryAfter = null,
)

private fun order(url: String = URL, times: OrderTimes = OrderTimes(null, null, null)) = AcmeOrder(
    url = url,
    status = AcmeStatus.Pending,
    identifiers = listOf(AcmeIdentifier.dns("a.b")),
    authorizations = emptyList(),
    finalize = URL,
    certificate = null,
    times = times,
    error = null,
    replaces = null,
    retryAfter = null,
)

private fun challenge(url: String = URL) = AcmeChallenge(
    url = url,
    type = "dns-01",
    kind = ChallengeType.Dns01,
    status = AcmeStatus.Pending,
    token = null,
    validated = null,
    error = null,
    retryAfter = null,
)

private fun authorization(url: String = URL) = AcmeAuthorization(
    url = url,
    identifier = AcmeIdentifier.dns("a.b"),
    status = AcmeStatus.Pending,
    challenges = emptyList(),
    expires = null,
    isWildcard = false,
    retryAfter = null,
)

private fun directory(newNonce: String = URL, meta: DirectoryMeta = meta()) = AcmeDirectory(
    newNonce = newNonce,
    newAccount = URL,
    newOrder = URL,
    newAuthorization = null,
    revokeCertificate = null,
    keyChange = null,
    renewalInfo = null,
    meta = meta,
)

private fun meta(website: String? = null) = DirectoryMeta(
    termsOfService = null,
    website = website,
    caaIdentities = emptyList(),
    isExternalAccountRequired = false,
)

private fun account(url: String = URL) = AcmeAccount(
    url = url,
    status = AcmeStatus.Valid,
    contacts = listOf("mailto:secret@example.org"),
    isTermsOfServiceAgreed = null,
    orders = null,
    isCreated = false,
)

private suspend fun certificate(): Certificate = Challenges(crypto).tlsAlpn01Certificate(
    identifier = AcmeIdentifier.dns("a.b"),
    keyAuthorization = Vectors.KEY_AUTHORIZATION,
    signer = signer(),
)

private fun renewal(id: String) =
    RenewalInfo(certificateId = id, start = TIME, end = TIME + 1.days, explanation = null, retryAfter = null)

class ValuesTest : FunSpec({
    test("compares and shows requests and responses") {
        val request = AcmeRequest(method = AcmeMethod.Post, url = URL, headers = listOf("Accept" to "a"))
        checkValue(
            value = request,
            same = AcmeRequest(method = AcmeMethod.Post, url = URL, headers = listOf("Accept" to "a")),
            others = listOf(AcmeRequest(method = AcmeMethod.Get, url = URL)),
        )
        request.header("accept") shouldBe "a"
        request.header("Content-Type") shouldBe null
        request.toString() shouldBe "AcmeRequest(POST $URL, 0 bytes)"
        val response = AcmeResponse(status = 200, headers = listOf("Link" to "1", "link" to "2", "X" to "3"))
        val same = AcmeResponse(status = 200, headers = response.headers)
        checkValue(value = response, same = same, others = listOf(AcmeResponse(status = 201)))
        response.headers("LINK") shouldBe listOf("1", "2")
        response.toString() shouldBe "AcmeResponse(200, 3 headers, 0 bytes)"
        shouldThrow<IllegalArgumentException> { AcmeResponse(status = 99) }
        shouldThrow<IllegalArgumentException> { AcmeResponse(status = 600) }
        AcmeMethod.entries.map { method -> method.methodName } shouldBe listOf("GET", "HEAD", "POST")
    }

    test("checks every limit against its ceiling") {
        checkValue(value = AcmeLimits(), same = AcmeLimits.Default, others = listOf(AcmeLimits(maximumEntries = 1)))
        AcmeLimits.Default.toString() shouldContain "maximumNonceRetries=3"
        val invalid = listOf<() -> AcmeLimits>(
            { AcmeLimits(maximumResponseBytes = 0) },
            { AcmeLimits(maximumResponseBytes = AcmeLimits.HARD_MAXIMUM_RESPONSE_BYTES + 1) },
            { AcmeLimits(maximumHeaders = 0) },
            { AcmeLimits(maximumHeaders = AcmeLimits.HARD_MAXIMUM_HEADERS + 1) },
            { AcmeLimits(maximumHeaderBytes = 0) },
            { AcmeLimits(maximumHeaderBytes = AcmeLimits.HARD_MAXIMUM_HEADER_BYTES + 1) },
            { AcmeLimits(maximumUrlLength = 0) },
            { AcmeLimits(maximumUrlLength = AcmeLimits.HARD_MAXIMUM_URL_LENGTH + 1) },
            { AcmeLimits(maximumEntries = 0) },
            { AcmeLimits(maximumEntries = AcmeLimits.HARD_MAXIMUM_ENTRIES + 1) },
            { AcmeLimits(maximumCertificates = 0) },
            { AcmeLimits(maximumCertificates = AcmeLimits.HARD_MAXIMUM_CERTIFICATES + 1) },
            { AcmeLimits(maximumNonces = 0) },
            { AcmeLimits(maximumNonces = AcmeLimits.HARD_MAXIMUM_NONCES + 1) },
            { AcmeLimits(maximumNonceRetries = -1) },
            { AcmeLimits(maximumNonceRetries = AcmeLimits.HARD_MAXIMUM_NONCE_RETRIES + 1) },
            { AcmeLimits(maximumRetryAfter = Duration.ZERO) },
            { AcmeLimits(maximumRetryAfter = AcmeLimits.HARD_MAXIMUM_RETRY_AFTER + 1.seconds) },
        )
        invalid.forEach { limits -> shouldThrow<IllegalArgumentException> { limits() } }
        val widest = AcmeLimits(
            maximumResponseBytes = AcmeLimits.HARD_MAXIMUM_RESPONSE_BYTES,
            maximumHeaders = AcmeLimits.HARD_MAXIMUM_HEADERS,
            maximumHeaderBytes = AcmeLimits.HARD_MAXIMUM_HEADER_BYTES,
            maximumUrlLength = AcmeLimits.HARD_MAXIMUM_URL_LENGTH,
            maximumEntries = AcmeLimits.HARD_MAXIMUM_ENTRIES,
            maximumCertificates = AcmeLimits.HARD_MAXIMUM_CERTIFICATES,
            maximumNonces = AcmeLimits.HARD_MAXIMUM_NONCES,
            maximumNonceRetries = 0,
            maximumRetryAfter = AcmeLimits.HARD_MAXIMUM_RETRY_AFTER,
            json = JoseLimits.Default,
        )
        widest.maximumRetryAfter shouldBe 7.days
    }

    test("compares and shows identifiers and finds the enums by name") {
        checkValue(
            value = AcmeIdentifier.dns("Example.ORG"),
            same = AcmeIdentifier.dns("example.org"),
            others = listOf(AcmeIdentifier.dns("example.net"), AcmeIdentifier.ip("192.0.2.1")),
        )
        AcmeIdentifier.dns("*.example.org").isWildcard shouldBe true
        AcmeIdentifier.ip("192.0.2.1").isWildcard shouldBe false
        AcmeIdentifier.dns("example.org").toString() shouldBe "dns:example.org"
        shouldThrow<IllegalArgumentException> { AcmeIdentifier.dns("a b") }
        shouldThrow<IllegalArgumentException> { AcmeIdentifier.ip("192.0.2") }
        AcmeProblemType.of("urn:ietf:params:acme:error:badCSR") shouldBe AcmeProblemType.BadCsr
        AcmeProblemType.of("badCSR") shouldBe null
        AcmeProblemType.AlreadyReplaced.urn shouldBe "urn:ietf:params:acme:error:alreadyReplaced"
        AcmeStatus.of("ready") shouldBe AcmeStatus.Ready
        AcmeStatus.of("Ready") shouldBe null
        IdentifierType.of("ip") shouldBe IdentifierType.Ip
        IdentifierType.of("email") shouldBe null
        ChallengeType.of("tls-alpn-01") shouldBe ChallengeType.TlsAlpn01
        ChallengeType.of("http-02") shouldBe null
    }

    test("checks account keys and external account bindings") {
        val key = accountKey()
        key.algorithm shouldBe JwsAlgorithm.ES256
        checkValue(
            value = key,
            same = AccountKey(key.privateKey),
            others = listOf(accountKey(), accountKey(KeyType.P384)),
        )
        key.toString() shouldBe "AccountKey(ES256)"
        val edwards = accountKey(KeyType.Ed25519)
        edwards.algorithm shouldBe JwsAlgorithm.EdDSA
        edwards shouldNotBe AccountKey(privateKey = edwards.privateKey, algorithm = JwsAlgorithm.Ed25519)
        listOf(JwsAlgorithm.ES384, JwsAlgorithm.HS256, JwsAlgorithm.RS256).forEach { algorithm ->
            shouldThrow<IllegalArgumentException> { AccountKey(privateKey = key.privateKey, algorithm = algorithm) }
        }
        val x25519 = crypto.keys.generate(KeyType.X25519).privateKey
        shouldThrow<IllegalArgumentException> { AccountKey(x25519) }
        val mac = SecretKey.of(SecretBytes.copyOf("0123456789abcdef0123456789abcdef".encodeToByteArray()))
        val binding = ExternalAccountBinding(keyId = "kid", key = mac)
        checkValue(
            value = binding,
            same = ExternalAccountBinding(keyId = "kid", key = mac, algorithm = JwsAlgorithm.HS256),
            others = listOf(
                ExternalAccountBinding(keyId = "other", key = mac),
                ExternalAccountBinding(keyId = "kid", key = SecretKey.of(SecretBytes.copyOf(ByteArray(MAC_BYTES)))),
                ExternalAccountBinding(keyId = "kid", key = mac, algorithm = JwsAlgorithm.HS512),
            ),
        )
        binding.toString() shouldNotContain "0123"
        shouldThrow<IllegalArgumentException> { ExternalAccountBinding(keyId = "", key = mac) }
        shouldThrow<IllegalArgumentException> {
            ExternalAccountBinding(keyId = "kid", key = mac, algorithm = JwsAlgorithm.ES256)
        }
    }

    test("compares and shows the resources of the server") {
        checkValue(value = problem(), same = problem(), others = listOf(problem(detail = null), problem(type = "x")))
        problem(detail = null).toString() shouldBe
            "AcmeProblem(urn:ietf:params:acme:error:dns, no detail, 0 subproblems)"
        checkValue(value = directory(), same = directory(), others = listOf(directory(newNonce = OTHER)))
        directory().toString() shouldBe "AcmeDirectory($URL)"
        checkValue(value = meta(), same = meta(), others = listOf(meta(website = URL)))
        meta().toString() shouldBe "DirectoryMeta(isExternalAccountRequired=false)"
        checkValue(value = account(), same = account(), others = listOf(account(url = OTHER)))
        account().toString() shouldBe "AcmeAccount($URL, valid)"
        val times = OrderTimes(expires = TIME, notBefore = TIME, notAfter = TIME)
        checkValue(value = order(), same = order(), others = listOf(order(url = OTHER), order(times = times)))
        order(times = times).expires shouldBe TIME
        order().toString() shouldBe "AcmeOrder($URL, pending, [dns:a.b])"
        checkValue(value = authorization(), same = authorization(), others = listOf(authorization(url = OTHER)))
        authorization().toString() shouldBe "AcmeAuthorization($URL, dns:a.b, pending)"
        checkValue(value = challenge(), same = challenge(), others = listOf(challenge(url = OTHER)))
        challenge().toString() shouldBe "AcmeChallenge(dns-01, pending)"
        val chain = CertificateChain(certificates = emptyList(), alternates = listOf(URL))
        checkValue(
            value = chain,
            same = CertificateChain(certificates = emptyList(), alternates = listOf(URL)),
            others = listOf(
                CertificateChain(certificates = emptyList(), alternates = emptyList()),
                CertificateChain(certificates = listOf(certificate()), alternates = listOf(URL)),
            ),
        )
        chain.toString() shouldBe "CertificateChain(0 certificates, 1 alternates)"
        val info = renewal("a.b")
        checkValue(value = info, same = renewal("a.b"), others = listOf(renewal("c.d")))
        info.toString() shouldContain "a.b"
    }
})
