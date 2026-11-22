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

package com.davils.krypt.testing.acme

import com.davils.krypt.acme.AcmeIdentifier
import com.davils.krypt.acme.AcmeMethod
import com.davils.krypt.acme.AcmeProblemType
import com.davils.krypt.acme.AcmeSession
import com.davils.krypt.acme.AcmeStatus
import com.davils.krypt.acme.account.AccountKey
import com.davils.krypt.acme.account.ExternalAccountBinding
import com.davils.krypt.acme.order.AcmeOrder
import com.davils.krypt.acme.order.ChallengeType
import com.davils.krypt.acme.renewal.CertificateIdentifiers
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.jose.jws.JwsSigner
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.request.CertificationRequests
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

private const val DOMAIN: String = "www.example.org"
private const val MALFORMED: String = "malformed"
private const val UNAUTHORIZED: String = "unauthorized"
private const val BAD_CSR: String = "badCSR"
private const val NEW_ACCOUNT: String = "$BASE/new-account"
private const val NEW_ORDER: String = "$BASE/new-order"
private const val CONTACT: String = "mailto:b@example.org"
private const val VALIDITY_DAYS: Int = 10

private suspend fun signer(): Signer = crypto.signatures.signer(crypto.keys.generate(KeyType.P256).privateKey)

private suspend fun ready(session: AcmeSession, identifiers: List<AcmeIdentifier>): AcmeOrder {
    val order = session.newOrder(identifiers).value()
    order.authorizations.forEach { url ->
        val authorization = session.authorization(url).value()
        session.respond(checkNotNull(authorization.challenge(ChallengeType.Dns01))).value()
    }
    return session.order(order.url).value()
}

private suspend fun csr(name: String, isBroken: Boolean = false): String {
    val request = CertificationRequests(crypto).create(signer()) {
        extensions { subjectAlternativeNames(names = listOf(GeneralName.Dns(name)), critical = true) }
    }
    val bytes = request.encoded.toByteArray()
    if (isBroken) bytes[bytes.size - 1] = (bytes.last() + 1).toByte()
    return base64(ByteString(bytes))
}

private fun signerOf(key: AccountKey): JwsSigner = JwsSigner(JoseKey.Private(key.privateKey), key.algorithm)

class FakeAcmeServerTest : FunSpec({
    test("serves a whole issuance to the client") {
        val server = FakeAcmeServer(crypto = crypto, processingPolls = 2)
        server.toString() shouldBe "FakeAcmeServer($BASE)"
        server.isPlainHttpAllowed shouldBe false
        val client = clientOf(server)
        val key = key()
        val created = client.newAccount(key = key, contacts = listOf("mailto:a@example.org")).value()
        val session = client.session(key = key, accountUrl = created.url)
        session.updateAccount(listOf(CONTACT)).value().contacts shouldBe listOf(CONTACT)
        session.account().value().contacts shouldBe listOf(CONTACT)
        val wildcard = AcmeIdentifier.dns("*.a.org")
        val identifiers = listOf(AcmeIdentifier.dns(DOMAIN), AcmeIdentifier.ip("192.0.2.1"), wildcard)
        val now = crypto.environment.clock.now()
        val order = session.newOrder(identifiers = identifiers, notBefore = now, notAfter = now + VALIDITY_DAYS.days)
        order.value().authorizations.forEach { url ->
            val authorization = session.authorization(url).value()
            val challenge = checkNotNull(authorization.challenge(ChallengeType.Dns01))
            session.challenge(challenge.url).value().status shouldBe AcmeStatus.Pending
            session.respond(challenge).value().status shouldBe AcmeStatus.Valid
            session.respond(challenge).problem() shouldBe AcmeProblemType.Malformed
        }
        val signer = signer()
        val readyOrder = session.order(order.value().url).value()
        val finalized = session.finalize(order = readyOrder, signer = signer).value()
        finalized.status shouldBe AcmeStatus.Processing
        session.finalize(order = finalized, signer = signer).problem() shouldBe AcmeProblemType.OrderNotReady
        val issued = session.awaitOrder(order = finalized, interval = Duration.ZERO).value()
        val chain = session.certificate(checkNotNull(issued.certificate)).value()
        chain.leaf.notAfter - chain.leaf.notBefore shouldBe VALIDITY_DAYS.days
        session.certificate(chain.alternates.single()).value().leaf shouldBe chain.leaf
        val info = client.renewalInfo(chain.leaf).value()
        val isOrdered = info.end > info.start
        isOrdered shouldBe true
        client.renewalInfo("AAAA.AAAA").problem() shouldBe AcmeProblemType.Malformed
        session.revoke(chain.leaf).value()
        session.revoke(chain.leaf).problem() shouldBe AcmeProblemType.AlreadyRevoked
        server.requests().first().method shouldBe AcmeMethod.Get
        shouldThrow<IllegalArgumentException> { server.rejectNextNonces(-1) }
    }

    test("binds external accounts, rolls keys over and deactivates") {
        val mac = macKey(0)
        val server = FakeAcmeServer(crypto = crypto, baseUrl = "http://acme.test", externalAccounts = mapOf(KID to mac))
        server.isPlainHttpAllowed shouldBe true
        val client = clientOf(server)
        val key = key()
        client.newAccount(key).problem() shouldBe AcmeProblemType.ExternalAccountRequired
        val wrongKey = ExternalAccountBinding(keyId = KID, key = macKey(1))
        client.newAccount(key = key, binding = wrongKey).problem() shouldBe AcmeProblemType.Unauthorized
        val wrongId = ExternalAccountBinding(keyId = "other", key = mac)
        client.newAccount(key = key, binding = wrongId).problem() shouldBe AcmeProblemType.Unauthorized
        val binding = ExternalAccountBinding(keyId = KID, key = mac)
        val account = client.newAccount(key = key, binding = binding).value()
        val session = client.session(key = key, accountUrl = account.url)
        val second = key()
        client.newAccount(key = second, binding = binding).value()
        session.changeKey(second).problem() shouldBe AcmeProblemType.Malformed
        val rolled = session.changeKey(key()).value()
        rolled.deactivateAccount().value().status shouldBe AcmeStatus.Deactivated
        rolled.account().problem() shouldBe AcmeProblemType.Unauthorized
    }

    test("refuses requests a server must refuse") {
        val server = FakeAcmeServer(crypto = crypto)
        val raw = RawRequests(server)
        val key = key()
        val stranger = key()
        val client = clientOf(server)
        val kid = client.newAccount(key).value().url
        val strangerAccount = client.newAccount(stranger).value()
        client.newAccount(stranger).value().isCreated shouldBe false
        server.rejectNextNonces(1)
        client.findAccount(stranger).value().url shouldBe strangerAccount.url
        raw.send(url = "$BASE/nothing", body = "", method = AcmeMethod.Get) shouldBe MALFORMED
        raw.send(url = "https://other.test/directory", body = "", method = AcmeMethod.Get) shouldBe MALFORMED
        raw.send(url = NEW_ACCOUNT, body = "not a JWS") shouldBe MALFORMED
        raw.send(url = NEW_ACCOUNT, body = jws.sign(payload = ByteString(), signer = signerOf(key))) shouldBe MALFORMED
        val twice = jws.signJson(payload = ByteString(), signers = listOf(signerOf(key), signerOf(key)))
        raw.send(url = NEW_ACCOUNT, body = twice) shouldBe MALFORMED
        raw.post(url = NEW_ACCOUNT, key = key, headerUrl = "$BASE/other") shouldBe UNAUTHORIZED
        raw.post(url = NEW_ACCOUNT, key = key, hasNonce = false) shouldBe "badNonce"
        raw.post(url = NEW_ACCOUNT, key = key, extra = listOf(KID to jsonText(kid))) shouldBe MALFORMED
        raw.post(url = "$BASE/order/1", key = key, kid = "$BASE/account/999") shouldBe "accountDoesNotExist"
        raw.post(url = "$BASE/order", key = key, kid = kid) shouldBe MALFORMED
        raw.post(url = NEW_ACCOUNT, key = key, kid = kid) shouldBe MALFORMED
        raw.post(url = NEW_ACCOUNT, key = key, payload = "[]") shouldBe MALFORMED
        val badKey = JsonValue.Object.of("kty" to jsonText("EC"))
        val badJwk = listOf(JWK to badKey, NONCE to jsonText(raw.nonce()), URL to jsonText(NEW_ACCOUNT))
        raw.send(url = NEW_ACCOUNT, body = raw.signed(payload = "", key = key, header = badJwk)) shouldBe "badPublicKey"
        val forged = listOf(JWK to jwkOf(stranger), NONCE to jsonText(raw.nonce()), URL to jsonText(NEW_ACCOUNT))
        raw.send(url = NEW_ACCOUNT, body = raw.signed(payload = "", key = key, header = forged)) shouldBe UNAUTHORIZED
        val existing = """{"onlyReturnExisting":true}"""
        raw.post(url = NEW_ACCOUNT, key = key(), payload = existing) shouldBe "accountDoesNotExist"
        raw.post(url = strangerAccount.url, key = key, kid = kid) shouldBe UNAUTHORIZED
        raw.post(url = kid, key = key, kid = kid, payload = """{"status":"pending"}""") shouldBe MALFORMED
        raw.post(url = kid, key = key, kid = kid, payload = """{"contact":[1]}""") shouldBe "invalidContact"
        raw.post(url = kid, key = key) shouldBe UNAUTHORIZED
    }

    test("refuses broken key changes") {
        val server = FakeAcmeServer(crypto = crypto)
        val raw = RawRequests(server)
        val key = key()
        val newKey = key()
        val client = clientOf(server)
        val kid = client.newAccount(key).value().url
        val url = "$BASE/key-change"
        val jwk = JWK to jwkOf(newKey)
        val target = URL to jsonText(url)
        val payload = """{"account":"$kid","oldKey":${jwkOf(key).encode()}}"""

        suspend fun change(content: String, header: List<Pair<String, JsonValue>>, signer: AccountKey = newKey) =
            raw.post(url = url, key = key, kid = kid, payload = raw.signed(content, signer, header))
        raw.post(url = url, key = key) shouldBe MALFORMED
        raw.post(url = url, key = key, kid = kid) shouldBe MALFORMED
        change(payload, listOf(KID to jsonText(kid), target)) shouldBe MALFORMED
        change(payload, listOf(jwk, URL to jsonText(kid))) shouldBe UNAUTHORIZED
        change(payload, listOf(jwk, target, NONCE to jsonText("n"))) shouldBe UNAUTHORIZED
        change(content = payload, header = listOf(jwk, target), signer = key) shouldBe UNAUTHORIZED
        change("", listOf(jwk, target)) shouldBe MALFORMED
        change("""{"account":"$kid"}""", listOf(jwk, target)) shouldBe MALFORMED
        change("""{"account":"$BASE/account/999","oldKey":${jwkOf(key).encode()}}""", listOf(jwk, target)) shouldBe
            UNAUTHORIZED
        change("""{"account":"$kid","oldKey":${jwkOf(newKey).encode()}}""", listOf(jwk, target)) shouldBe UNAUTHORIZED
        change("""{"account":"$kid","oldKey":{"kty":"EC"}}""", listOf(jwk, target)) shouldBe "badPublicKey"
        change(payload, listOf(jwk, target)) shouldBe OK
    }

    test("refuses an external account binding over another key") {
        val mac = macKey(0)
        val server = FakeAcmeServer(crypto = crypto, externalAccounts = mapOf(KID to mac))
        val raw = RawRequests(server)
        val key = key()
        val binding = raw.signed(
            payload = jwkOf(key()).encode(),
            key = key,
            header = listOf(KID to jsonText(KID), URL to jsonText(NEW_ACCOUNT)),
            signer = JoseKey.Secret(mac),
            algorithm = JwsAlgorithm.HS256,
        )
        raw.post(url = NEW_ACCOUNT, key = key, payload = """{"externalAccountBinding":$binding}""") shouldBe
            UNAUTHORIZED
    }

    test("refuses broken orders, authorizations and challenges") {
        val server = FakeAcmeServer(crypto = crypto)
        val raw = RawRequests(server)
        val key = key()
        val stranger = key()
        val client = clientOf(server)
        val kid = client.newAccount(key).value().url
        val strangerKid = client.newAccount(stranger).value().url
        val session = client.session(key = key, accountUrl = kid)
        raw.post(url = NEW_ORDER, key = key, payload = """{"identifiers":[]}""") shouldBe MALFORMED
        val refused = listOf(
            """{"identifiers":[]}""" to MALFORMED,
            """{"identifiers":["a.b"]}""" to MALFORMED,
            """{"identifiers":[{"value":"a.b"}]}""" to MALFORMED,
            """{"identifiers":[{"type":"email","value":"a@b.c"}]}""" to "unsupportedIdentifier",
            """{"identifiers":[{"type":"dns"}]}""" to MALFORMED,
            """{"identifiers":[{"type":"dns","value":"a_b"}]}""" to "rejectedIdentifier",
            """{"identifiers":[{"type":"dns","value":"a.b"}],"replaces":"AAAA.AAAA"}""" to MALFORMED,
        )
        refused.forEach { (payload, code) ->
            raw.post(url = NEW_ORDER, key = key, kid = kid, payload = payload) shouldBe code
        }
        val order = ready(session = session, identifiers = listOf(AcmeIdentifier.dns(DOMAIN)))
        val authorization = order.authorizations.single()
        raw.post(url = authorization, key = stranger, kid = strangerKid) shouldBe UNAUTHORIZED
        raw.post(url = authorization, key = key, kid = kid, payload = """{"status":"pending"}""") shouldBe MALFORMED
        raw.post(url = order.url, key = key) shouldBe UNAUTHORIZED
        val finalize = order.finalize
        raw.post(url = finalize, key = key, kid = kid, payload = "{}") shouldBe BAD_CSR
        raw.post(url = finalize, key = key, kid = kid, payload = """{"csr":"!!"}""") shouldBe MALFORMED
        raw.post(url = finalize, key = key, kid = kid, payload = """{"csr":"${csr("other.org")}"}""") shouldBe BAD_CSR
        val broken = csr(name = DOMAIN, isBroken = true)
        raw.post(url = finalize, key = key, kid = kid, payload = """{"csr":"$broken"}""") shouldBe BAD_CSR
        raw.post(url = finalize, key = key, kid = kid, payload = """{"csr":"${csr(DOMAIN)}"}""") shouldBe OK
        session.deactivateAuthorization(authorization).value().status shouldBe AcmeStatus.Deactivated
    }

    test("refuses broken downloads, replacements and revocations") {
        val server = FakeAcmeServer(crypto = crypto)
        val raw = RawRequests(server)
        val key = key()
        val stranger = key()
        val client = clientOf(server)
        val kid = client.newAccount(key).value().url
        val strangerKid = client.newAccount(stranger).value().url
        val session = client.session(key = key, accountUrl = kid)
        val order = ready(session = session, identifiers = listOf(AcmeIdentifier.dns(DOMAIN)))
        val certificate = checkNotNull(session.finalize(order = order, signer = signer()).value().certificate)
        raw.post(url = certificate, key = stranger, kid = strangerKid) shouldBe UNAUTHORIZED
        raw.post(url = "$BASE/cert", key = key, kid = kid) shouldBe MALFORMED
        val leaf = session.certificate(certificate).value().leaf
        val identifier = checkNotNull(CertificateIdentifiers.of(leaf))
        val replacing = """{"identifiers":[{"type":"dns","value":"$DOMAIN"}],"replaces":"$identifier"}"""
        raw.post(url = NEW_ORDER, key = stranger, kid = strangerKid, payload = replacing) shouldBe UNAUTHORIZED
        val replacement = session.newOrder(identifiers = order.identifiers, replaces = identifier).value()
        raw.post(url = NEW_ORDER, key = key, kid = kid, payload = replacing) shouldBe "alreadyReplaced"
        val again = ready(session = session, identifiers = replacement.identifiers)
        session.finalize(order = again, signer = signer()).value().status shouldBe AcmeStatus.Valid
        val revoke = "$BASE/revoke-cert"
        val der = """{"certificate":"${base64(leaf.encoded)}""""
        raw.post(url = revoke, key = key, kid = kid) shouldBe MALFORMED
        raw.post(url = revoke, key = key, kid = kid, payload = """{"certificate":"AAAA"}""") shouldBe MALFORMED
        raw.post(url = revoke, key = stranger, kid = strangerKid, payload = "$der}") shouldBe UNAUTHORIZED
        raw.post(url = revoke, key = key(), payload = "$der}") shouldBe UNAUTHORIZED
        raw.post(url = revoke, key = key, kid = kid, payload = """$der,"reason":7}""") shouldBe "badRevocationReason"
        raw.post(url = revoke, key = key, kid = kid, payload = """$der,"reason":4}""") shouldBe OK
    }
})
