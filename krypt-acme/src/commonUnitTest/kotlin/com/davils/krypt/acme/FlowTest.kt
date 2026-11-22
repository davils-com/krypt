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

import com.davils.krypt.acme.account.ExternalAccountBinding
import com.davils.krypt.acme.fixture.accountKey
import com.davils.krypt.acme.fixture.clientOf
import com.davils.krypt.acme.fixture.crypto
import com.davils.krypt.acme.fixture.failure
import com.davils.krypt.acme.fixture.problem
import com.davils.krypt.acme.fixture.signer
import com.davils.krypt.acme.fixture.value
import com.davils.krypt.acme.order.AcmeOrder
import com.davils.krypt.acme.order.ChallengeType
import com.davils.krypt.acme.order.Challenges
import com.davils.krypt.acme.renewal.CertificateIdentifiers
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.testing.acme.FakeAcmeServer
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.name.GeneralName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

private const val CONTACT: String = "mailto:admin@example.org"
private const val DOMAIN: String = "www.example.org"
private const val ADDRESS: String = "192.0.2.7"
private const val MAC_BYTES: Int = 32
private const val REJECTED: Int = 3
private const val VALIDITY_DAYS: Int = 30

private suspend fun ready(
    session: AcmeSession,
    identifiers: List<AcmeIdentifier>,
    replaces: String? = null,
): AcmeOrder {
    val order = session.newOrder(identifiers = identifiers, replaces = replaces).value()
    order.authorizations.forEach { url ->
        val authorization = session.authorization(url).value()
        val challenge = authorization.challenge(ChallengeType.Dns01).shouldNotBeNull()
        session.respond(challenge).value().status shouldBe AcmeStatus.Valid
        val awaited = session.awaitAuthorization(authorization = authorization, interval = Duration.ZERO)
        awaited.value().status shouldBe AcmeStatus.Valid
    }
    return session.awaitOrder(order = order, interval = Duration.ZERO).value()
}

class FlowTest : FunSpec({
    test("creates an account, orders, validates, finalizes, downloads and revokes") {
        val server = FakeAcmeServer(crypto = crypto, processingPolls = 2)
        val client = clientOf(server)
        val key = accountKey()
        val directory = client.directory().value()
        directory.meta.termsOfService shouldBe "https://acme.test/terms"
        directory.meta.caaIdentities shouldContainExactly listOf("acme.test")
        val account = client.newAccount(key = key, contacts = listOf(CONTACT), isTermsOfServiceAgreed = true).value()
        account.isCreated shouldBe true
        account.contacts shouldContainExactly listOf(CONTACT)
        client.newAccount(key).value().isCreated shouldBe false
        client.findAccount(key).value().url shouldBe account.url
        val session = client.session(key = key, accountUrl = account.url)
        session.account().value().status shouldBe AcmeStatus.Valid
        val identifiers = listOf(AcmeIdentifier.dns(DOMAIN), AcmeIdentifier.ip(ADDRESS))
        val now = crypto.environment.clock.now()
        val notAfter = now + VALIDITY_DAYS.days
        val ordered = session.newOrder(identifiers = identifiers, notBefore = now, notAfter = notAfter).value()
        ordered.status shouldBe AcmeStatus.Pending
        ordered.identifiers shouldContainExactly identifiers
        ordered.notBefore.shouldNotBeNull()
        val authorization = session.authorization(ordered.authorizations.first()).value()
        authorization.identifier shouldBe AcmeIdentifier.dns(DOMAIN)
        val http = authorization.challenge(ChallengeType.Http01).shouldNotBeNull()
        val keyAuthorization = session.keyAuthorization(http)
        val token = http.token.orEmpty()
        keyAuthorization shouldStartWith token
        client.challenges.http01Path(token) shouldBe "/.well-known/acme-challenge/$token"
        session.challenge(http.url).value().status shouldBe AcmeStatus.Pending
        session.respond(http).value().status shouldBe AcmeStatus.Valid
        val address = session.authorization(ordered.authorizations.last()).value()
        val alpn = address.challenge(ChallengeType.TlsAlpn01).shouldNotBeNull()
        val validation = client.challenges.tlsAlpn01Certificate(
            identifier = address.identifier,
            keyAuthorization = session.keyAuthorization(alpn),
            signer = signer(),
        )
        validation.extensions[Challenges.ACME_IDENTIFIER].shouldNotBeNull().isCritical shouldBe true
        session.respond(alpn).value().status shouldBe AcmeStatus.Valid
        val readyOrder = session.awaitOrder(order = ordered, interval = Duration.ZERO).value()
        readyOrder.status shouldBe AcmeStatus.Ready
        val finalized = session.finalize(order = readyOrder, signer = signer()).value()
        finalized.status shouldBe AcmeStatus.Processing
        finalized.retryAfter shouldBe null
        val issued = session.awaitOrder(order = finalized, interval = Duration.ZERO).value()
        issued.status shouldBe AcmeStatus.Valid
        val chain = session.certificate(issued.certificate.orEmpty()).value()
        chain.certificates shouldHaveSize 2
        chain.leaf.extensions.subjectAlternativeNames shouldContainExactly listOf(
            GeneralName.Dns(DOMAIN),
            checkNotNull(GeneralName.IpAddress.parseOrNull(ADDRESS)),
        )
        chain.alternates shouldHaveSize 1
        val alternate = session.certificate(chain.alternates.single()).value()
        alternate.leaf shouldBe chain.leaf
        alternate.alternates shouldHaveSize 0
        val renewal = client.renewalInfo(chain.leaf).value()
        renewal.certificateId shouldBe CertificateIdentifiers.of(chain.leaf)
        renewal.isRenewalDue(renewal.start) shouldBe true
        renewal.retryAfter shouldBe Duration.parse("6h")
        session.revoke(certificate = chain.leaf, reason = RevocationReason.Superseded).value()
        session.revoke(chain.leaf).problem() shouldBe AcmeProblemType.AlreadyRevoked
        val requests = server.requests()
        requests.first { request -> request.url == issued.certificate }.header("Accept") shouldBe
            "application/pem-certificate-chain"
        requests.last().header("Content-Type") shouldBe "application/jose+json"
    }

    test("replaces a certificate once and revokes with the key of the certificate") {
        val server = FakeAcmeServer(crypto = crypto)
        val client = clientOf(server)
        val key = accountKey()
        val session = client.session(key = key, accountUrl = client.newAccount(key).value().url)
        val identifiers = listOf(AcmeIdentifier.dns("*.example.org"))
        val order = ready(session = session, identifiers = identifiers)
        order.status shouldBe AcmeStatus.Ready
        val certificateKey = accountKey()
        val certificateSigner = crypto.signatures.signer(certificateKey.privateKey)
        val issued = session.finalize(order = order, signer = certificateSigner).value()
        issued.status shouldBe AcmeStatus.Valid
        val leaf = session.certificate(issued.certificate.orEmpty()).value().leaf
        val id = checkNotNull(CertificateIdentifiers.of(leaf))
        val replacing = ready(session = session, identifiers = identifiers, replaces = id)
        replacing.replaces shouldBe id
        session.newOrder(identifiers = identifiers, replaces = id).problem() shouldBe AcmeProblemType.AlreadyReplaced
        client.revoke(certificate = leaf, certificateKey = certificateKey).value()
    }

    test("binds a new account to an external account") {
        val macKey = SecretKey.of(SecretBytes.copyOf(ByteArray(MAC_BYTES) { index -> index.toByte() }))
        val server = FakeAcmeServer(crypto = crypto, externalAccounts = mapOf("kid-1" to macKey))
        val client = clientOf(server)
        val directory = client.directory().value()
        directory.meta.isExternalAccountRequired shouldBe true
        val key = accountKey()
        client.newAccount(key).problem() shouldBe AcmeProblemType.ExternalAccountRequired
        val unknown = ExternalAccountBinding(keyId = "kid-2", key = macKey)
        client.newAccount(key = key, binding = unknown).problem() shouldBe AcmeProblemType.Unauthorized
        val binding = ExternalAccountBinding(keyId = "kid-1", key = macKey)
        client.newAccount(key = key, binding = binding).value().isCreated shouldBe true
    }

    test("rolls the key over, updates and deactivates the account") {
        val server = FakeAcmeServer(crypto = crypto)
        val client = clientOf(server)
        val oldKey = accountKey()
        val account = client.newAccount(oldKey).value()
        val session = client.session(key = oldKey, accountUrl = account.url)
        session.updateAccount(listOf(CONTACT)).value().contacts shouldContainExactly listOf(CONTACT)
        val newKey = accountKey()
        val rolled = session.changeKey(newKey).value()
        rolled.key shouldBe newKey
        rolled.account().value().url shouldBe account.url
        client.findAccount(oldKey).problem() shouldBe AcmeProblemType.AccountDoesNotExist
        client.findAccount(newKey).value().url shouldBe account.url
        session.changeKey(newKey).problem() shouldBe AcmeProblemType.Unauthorized
        val order = rolled.newOrder(listOf(AcmeIdentifier.dns(DOMAIN))).value()
        val deactivated = rolled.deactivateAuthorization(order.authorizations.single()).value()
        deactivated.status shouldBe AcmeStatus.Deactivated
        rolled.deactivateAccount().value().status shouldBe AcmeStatus.Deactivated
        rolled.account().problem() shouldBe AcmeProblemType.Unauthorized
    }

    test("retries a bad nonce a bounded number of times") {
        val server = FakeAcmeServer(crypto = crypto)
        val client = clientOf(server, AcmeLimits(maximumNonceRetries = 2))
        val key = accountKey()
        server.rejectNextNonces(2)
        client.newAccount(key).value().isCreated shouldBe true
        server.rejectNextNonces(REJECTED)
        client.findAccount(key).problem() shouldBe AcmeProblemType.BadNonce
        client.findAccount(key).value().isCreated shouldBe false
    }

    test("gives up polling an order in time and accepts plain http only where the transport allows it") {
        val server = FakeAcmeServer(crypto = crypto, baseUrl = "http://acme.test", processingPolls = 3)
        val client = clientOf(server)
        val key = accountKey()
        val session = client.session(key = key, accountUrl = client.newAccount(key).value().url)
        val order = ready(session = session, identifiers = listOf(AcmeIdentifier.dns(DOMAIN)))
        val finalized = session.finalize(order = order, signer = signer()).value()
        session.awaitOrder(order = finalized, maximumPolls = 1, interval = Duration.ZERO).failure() shouldBe
            AcmeError.PollsExhausted
        session.order(order.url).value().status shouldBe AcmeStatus.Processing
        session.order("https://acme.test/order/1").problem() shouldBe AcmeProblemType.Malformed
    }
})
