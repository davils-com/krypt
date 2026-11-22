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

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.acme.account.AcmeAccount
import com.davils.krypt.acme.fixture.DIRECTORY_URL
import com.davils.krypt.acme.fixture.NONCE
import com.davils.krypt.acme.fixture.ScriptedTransport
import com.davils.krypt.acme.fixture.Vectors
import com.davils.krypt.acme.fixture.accountKey
import com.davils.krypt.acme.fixture.clientOf
import com.davils.krypt.acme.fixture.crypto
import com.davils.krypt.acme.fixture.failure
import com.davils.krypt.acme.fixture.problem
import com.davils.krypt.acme.fixture.problemResponse
import com.davils.krypt.acme.fixture.response
import com.davils.krypt.acme.fixture.signer
import com.davils.krypt.acme.fixture.value
import com.davils.krypt.acme.order.Challenges
import com.davils.krypt.jose.JoseLimits
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private const val ACCOUNT_URL: String = "https://ca.test/acct/1"
private const val ORDER_URL: String = "https://ca.test/order/1"
private const val AUTHZ_URL: String = "https://ca.test/authz/1"
private const val ACCOUNT: String = """{"status":"valid"}"""
private const val ORDER: String = """{"status":"pending","identifiers":[{"type":"dns","value":"a.b"}],""" +
    """"authorizations":["$AUTHZ_URL"],"finalize":"https://ca.test/finalize/1"}"""
private const val VALID_ORDER: String = """{"status":"valid","identifiers":[{"type":"dns","value":"a.b"}],""" +
    """"authorizations":[],"finalize":"https://ca.test/finalize/1"}"""
private const val AUTHZ: String = """{"identifier":{"type":"dns","value":"a.b"},"status":"pending",""" +
    """"challenges":[{"type":"x-01","url":"https://ca.test/ch/1","status":"pending"}]}"""
private const val MINIMAL_DIRECTORY: String =
    """{"newNonce":"https://ca.test/nonce","newAccount":"https://ca.test/account","newOrder":"https://ca.test/order"}"""
private const val PROBLEM: String =
    """{"type":"urn:ietf:params:acme:error:serverInternal","detail":"later","status":503}"""
private const val BAD_NONCE: String = """{"type":"urn:ietf:params:acme:error:badNonce"}"""
private const val NONCE_HEADER: String = "Replay-Nonce"
private const val RENEWAL: String =
    """{"suggestedWindow":{"start":"2027-01-01T00:00:00Z","end":"2027-01-02T00:00:00Z"}}"""
private const val LOCATION: String = "Location"
private const val RETRY_AFTER: String = "Retry-After"
private const val PLAIN_DIRECTORY: String = "http://ca.test"
private const val SMALL: Int = 64
private const val UNAVAILABLE: Int = 503
private const val TOO_MANY_POLLS: Int = 1_001
private const val RETRY_SECONDS: Int = 30

private fun scripted(vararg answers: AcmeResponse): ScriptedTransport = ScriptedTransport(answers.toList())

private suspend fun sessionOf(transport: ScriptedTransport, limits: AcmeLimits = AcmeLimits.Default): AcmeSession {
    val client = clientOf(transport = transport, limits = limits)
    return client.session(key = accountKey(), accountUrl = ACCOUNT_URL)
}

private suspend fun directoryFailure(transport: AcmeTransport, limits: AcmeLimits = AcmeLimits.Default): AcmeFailure? {
    val client = clientOf(transport = transport, limits = limits)
    return client.directory().failure()
}

private suspend fun newAccount(transport: AcmeTransport): Outcome<AcmeAccount, AcmeFailure> {
    val client = clientOf(transport)
    return client.newAccount(accountKey())
}

class HostileTest : FunSpec({
    test("contains a transport that throws") {
        directoryFailure(AcmeTransport { _ -> error("boom") }) shouldBe AcmeError.Transport
    }

    test("checks the size of the body and of the header fields of every response") {
        val limits = AcmeLimits(maximumResponseBytes = SMALL, maximumHeaders = 2, maximumHeaderBytes = SMALL)
        directoryFailure(transport = scripted(), limits = limits) shouldBe AcmeError.LimitExceeded
        val crowded = listOf("A" to "1", "B" to "2", "C" to "3")
        val manyHeaders = ScriptedTransport(answers = emptyList(), directory = response(headers = crowded))
        directoryFailure(transport = manyHeaders, limits = limits) shouldBe AcmeError.LimitExceeded
        val long = response(headers = listOf("A" to "x".repeat(SMALL)))
        val longHeader = ScriptedTransport(answers = emptyList(), directory = long)
        directoryFailure(transport = longHeader, limits = limits) shouldBe AcmeError.LimitExceeded
        val deep = AcmeLimits(json = JoseLimits(maximumDepth = 1))
        directoryFailure(transport = scripted(), limits = deep) shouldBe AcmeError.LimitExceeded
        val broken = ScriptedTransport(answers = emptyList(), directory = response(body = "{"))
        directoryFailure(broken) shouldBe AcmeError.Malformed
    }

    test("reads the directory once") {
        val transport = scripted()
        val client = clientOf(transport)
        client.directory().value() shouldBe client.directory().value()
        transport.requests.size shouldBe 1
        client.toString() shouldBe "AcmeClient($DIRECTORY_URL)"
    }

    test("refuses broken nonces and header fields") {
        val created = response(status = 201, body = ACCOUNT, headers = listOf(LOCATION to ACCOUNT_URL))
        val nonces = listOf(
            response(),
            response(headers = listOf(NONCE_HEADER to "a+b")),
            response(headers = listOf(NONCE_HEADER to NONCE, NONCE_HEADER to NONCE)),
        )
        nonces.forEach { nonce ->
            val transport = ScriptedTransport(answers = listOf(created), nonce = nonce)
            newAccount(transport).failure() shouldBe AcmeError.Malformed
        }
        val failing = ScriptedTransport(answers = listOf(created), nonce = response(status = 500))
        newAccount(failing).failure() shouldBe AcmeError.UnexpectedStatus
        val answers = listOf(
            response(status = 201, body = ACCOUNT, headers = listOf(RETRY_AFTER to "1", RETRY_AFTER to "2")),
            response(status = 201, body = ACCOUNT, headers = listOf(RETRY_AFTER to "soon")),
            response(status = 201, body = ACCOUNT, headers = listOf("Link" to "<broken")),
            response(status = 201, body = ACCOUNT),
        )
        answers.forEach { answer -> newAccount(scripted(answer)).failure() shouldBe AcmeError.Malformed }
        val insecure = response(status = 201, body = ACCOUNT, headers = listOf(LOCATION to "http://ca.test/acct"))
        newAccount(scripted(insecure)).failure() shouldBe AcmeError.InsecureUrl
        val existing = response(body = ACCOUNT, headers = listOf(LOCATION to ACCOUNT_URL))
        newAccount(scripted(existing)).value().isCreated shouldBe false
    }

    test("reads problem documents and unexpected statuses") {
        val unavailable = ScriptedTransport(answers = emptyList(), directory = response(status = 500))
        directoryFailure(unavailable) shouldBe AcmeError.UnexpectedStatus
        val problem = problemResponse(body = PROBLEM, status = UNAVAILABLE, headers = listOf(RETRY_AFTER to "30"))
        val failed = directoryFailure(ScriptedTransport(answers = emptyList(), directory = problem))
        val found = failed.shouldBeInstanceOf<AcmeProblem>()
        found.kind shouldBe AcmeProblemType.ServerInternal
        found.status shouldBe UNAVAILABLE
        found.retryAfter shouldBe RETRY_SECONDS.seconds
        found.detail shouldBe "later"
        val session = sessionOf(scripted(response(body = ORDER, headers = listOf(LOCATION to ORDER_URL))))
        session.newOrder(listOf(AcmeIdentifier.dns("a.b"))).failure() shouldBe AcmeError.UnexpectedStatus
        val missingLocation = sessionOf(scripted(response(status = 201, body = ORDER)))
        missingLocation.newOrder(listOf(AcmeIdentifier.dns("a.b"))).failure() shouldBe AcmeError.Malformed
        val transport = scripted(problemResponse(BAD_NONCE))
        val strict = sessionOf(transport = transport, limits = AcmeLimits(maximumNonceRetries = 0))
        strict.account().problem() shouldBe AcmeProblemType.BadNonce
        transport.requests.count { request -> request.method == AcmeMethod.Post } shouldBe 1
        val array = sessionOf(scripted(response(body = "[]")))
        array.account().failure() shouldBe AcmeError.Malformed
    }

    test("reports what the server does not offer") {
        val minimal = ScriptedTransport(answers = emptyList(), directory = response(body = MINIMAL_DIRECTORY))
        val client = clientOf(minimal)
        val key = accountKey()
        val session = client.session(key = key, accountUrl = ACCOUNT_URL)
        session.changeKey(accountKey()).failure() shouldBe AcmeError.Unsupported
        client.renewalInfo(Vectors.RFC9773_IDENTIFIER).failure() shouldBe AcmeError.Unsupported
        val certificate = Challenges(crypto).tlsAlpn01Certificate(
            identifier = AcmeIdentifier.dns("a.b"),
            keyAuthorization = Vectors.KEY_AUTHORIZATION,
            signer = signer(),
        )
        client.revoke(certificate = certificate, certificateKey = key).failure() shouldBe AcmeError.Unsupported
        client.renewalInfo(certificate).failure() shouldBe AcmeError.Unsupported
        val transport = scripted(response(body = RENEWAL))
        val renewing = clientOf(transport)
        renewing.renewalInfo(Vectors.RFC9773_IDENTIFIER).value().retryAfter shouldBe null
        transport.requests.last().url shouldBe "https://ca.test/renewal/${Vectors.RFC9773_IDENTIFIER}"
    }

    test("refuses invalid input of the caller") {
        val client = clientOf(scripted())
        shouldThrow<IllegalArgumentException> { client.session(accountKey(), "http://ca.test/acct") }
        shouldThrow<IllegalArgumentException> { client.renewalInfo("nope") }
        shouldThrow<IllegalArgumentException> {
            AcmeClient(transport = scripted(), directoryUrl = PLAIN_DIRECTORY, crypto = crypto)
        }
        val allowing = ScriptedTransport(answers = emptyList(), isPlainHttpAllowed = true)
        val plain = AcmeClient(transport = allowing, directoryUrl = PLAIN_DIRECTORY, crypto = crypto)
        plain.directoryUrl shouldBe PLAIN_DIRECTORY
        val session = sessionOf(scripted(response(body = AUTHZ)))
        val now = crypto.environment.clock.now()
        val identifiers = listOf(AcmeIdentifier.dns("a.b"))
        shouldThrow<IllegalArgumentException> { session.newOrder(emptyList()) }
        shouldThrow<IllegalArgumentException> {
            session.newOrder(identifiers = identifiers, notBefore = now, notAfter = now)
        }
        shouldThrow<IllegalArgumentException> { session.newOrder(identifiers = identifiers, replaces = "nope") }
        session.newOrder(identifiers = identifiers, notBefore = now).failure() shouldBe AcmeError.UnexpectedStatus
        session.newOrder(identifiers = identifiers, notAfter = now).failure() shouldBe AcmeError.UnexpectedStatus
        val authorization = session.authorization(AUTHZ_URL).value()
        shouldThrow<IllegalArgumentException> { session.keyAuthorization(authorization.challenges.single()) }
        listOf(0, TOO_MANY_POLLS).forEach { polls ->
            shouldThrow<IllegalArgumentException> {
                session.awaitAuthorization(authorization = authorization, maximumPolls = polls)
            }
        }
        shouldThrow<IllegalArgumentException> {
            session.awaitAuthorization(authorization = authorization, interval = (-1).seconds)
        }
        session.order("http://ca.test/order").failure() shouldBe AcmeError.InsecureUrl
        session.toString() shouldBe "AcmeSession($ACCOUNT_URL, ${session.key})"
    }

    test("polls until the resource settles, the polls run out or a poll fails") {
        val pending = sessionOf(scripted(response(body = AUTHZ, headers = listOf(RETRY_AFTER to "0"))))
        val authorization = pending.authorization(AUTHZ_URL).value()
        val exhausted =
            pending.awaitAuthorization(authorization = authorization, maximumPolls = 2, interval = Duration.ZERO)
        exhausted.failure() shouldBe AcmeError.PollsExhausted
        val failing = sessionOf(scripted(response(body = AUTHZ), response(status = 500)))
        val first = failing.authorization(AUTHZ_URL).value()
        val failed = failing.awaitAuthorization(authorization = first, interval = Duration.ZERO)
        failed.failure() shouldBe AcmeError.UnexpectedStatus
        val orders = sessionOf(scripted(response(body = ORDER), response(body = VALID_ORDER), response(status = 500)))
        val order = orders.order(ORDER_URL).value()
        val valid = orders.awaitOrder(order = order, interval = Duration.ZERO).value()
        valid.status shouldBe AcmeStatus.Valid
        orders.awaitOrder(order = valid, interval = Duration.ZERO).value() shouldBe valid
        orders.awaitOrder(order = order, interval = Duration.ZERO).failure() shouldBe AcmeError.UnexpectedStatus
    }
})
