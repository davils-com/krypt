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

package com.davils.krypt.tls.trust

import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.ct.LogList
import com.davils.krypt.ct.ctPolicy
import com.davils.krypt.tls.ClientAuthentication
import com.davils.krypt.tls.TlsContext
import com.davils.krypt.tls.TlsRole
import com.davils.krypt.tls.fixture.HOST
import com.davils.krypt.tls.fixture.OTHER_HOST
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.StubEngine
import com.davils.krypt.tls.fixture.StubSession
import com.davils.krypt.tls.fixture.TestLog
import com.davils.krypt.tls.fixture.clientConfiguration
import com.davils.krypt.tls.fixture.crypto
import com.davils.krypt.tls.fixture.mutual
import com.davils.krypt.tls.fixture.serverConfiguration
import com.davils.krypt.tls.internal.JcaCertificates
import com.davils.krypt.tls.peer.PeerIdentity
import com.davils.krypt.tls.tls
import com.davils.krypt.x509.path.PathFailure
import com.davils.krypt.x509.path.RevocationStatus
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.net.Socket
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLHandshakeException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

private const val AUTH_TYPE: String = "EC"
private const val DEPTH: Int = 40

private fun refuses(check: () -> Unit) {
    shouldThrow<TrustRefusedException> { check() }
}

class TrustValuesTest : FunSpec({
    test("every path failure maps to the trust failure of the same name") {
        PathFailure.entries.forEach { failure -> TrustFailure.of(failure).name shouldBe failure.name }
    }

    test("the failure of a refusal is found by type in the causes, within bounds") {
        val refusal = TrustRefusedException(TrustFailure.Revoked)
        refusal.message shouldBe "The peer is not trusted: Revoked"
        val wrapped = SSLHandshakeException("certificate_unknown")
        wrapped.initCause(refusal)
        TrustFailure.of(wrapped) shouldBe TrustFailure.Revoked
        TrustFailure.of(IllegalStateException(TrustFailure.Revoked.name)).shouldBeNull()
        val first = IllegalStateException("first")
        val second = IllegalStateException("second", first)
        first.initCause(second)
        TrustFailure.of(first).shouldBeNull()
        val deep = (1..DEPTH).fold<Int, Throwable>(refusal) { cause, _ -> IllegalStateException(cause) }
        TrustFailure.of(deep).shouldBeNull()
    }

    test("a cached status expires at the next update of its answer when that comes before its lifetime") {
        val pki = Pki.create()
        val certificate = pki.identity(CertificateProfile.TlsServer, SERVER_NAME).certificate
        val now = crypto.environment.clock.now()
        val cache = RevocationCache(lifetime = 1.hours)
        cache.put(certificate = certificate, status = RevocationStatus.Good, at = now, nextUpdate = now + 10.minutes)
        cache.status(certificate, now + 9.minutes) shouldBe RevocationStatus.Good
        cache.status(certificate, now + 10.minutes).shouldBeNull()
        cache.put(certificate = certificate, status = RevocationStatus.Good, at = now, nextUpdate = now + 2.hours)
        cache.status(certificate, now + 59.minutes) shouldBe RevocationStatus.Good
        cache.status(certificate, now + 1.hours).shouldBeNull()
        cache.put(certificate = certificate, status = RevocationStatus.Revoked, at = now, nextUpdate = now)
        cache.status(certificate, now).shouldBeNull()
        cache.size shouldBe 0
    }

    test("the revocation cache keeps statuses for their lifetime and within its capacity") {
        val pki = Pki.create()
        val first = pki.identity(CertificateProfile.TlsServer, SERVER_NAME).certificate
        val second = pki.identity(CertificateProfile.TlsServer, SERVER_NAME).certificate
        val third = pki.identity(CertificateProfile.TlsServer, SERVER_NAME).certificate
        val now = crypto.environment.clock.now()
        val cache = RevocationCache(capacity = 2, lifetime = 1.hours)
        cache.put(first, RevocationStatus.Unknown, now)
        cache.size shouldBe 0
        cache.put(first, RevocationStatus.Good, now)
        cache.put(first, RevocationStatus.Revoked, now)
        cache.status(first, now) shouldBe RevocationStatus.Revoked
        cache.put(second, RevocationStatus.Good, now + 1.minutes)
        cache.put(third, RevocationStatus.Good, now + 2.minutes)
        cache.size shouldBe 2
        cache.status(first, now).shouldBeNull()
        cache.status(second, now + 1.hours + 1.minutes).shouldBeNull()
        cache.status(third, now + 1.hours + 1.minutes) shouldBe RevocationStatus.Good
        cache.prune(now + 1.hours + 1.minutes) shouldBe 1
        cache.prune(now) shouldBe 0
        cache.toString() shouldContain "size=1"
        cache.clear()
        cache.size shouldBe 0
        shouldThrow<IllegalArgumentException> { RevocationCache(capacity = 0) }
        shouldThrow<IllegalArgumentException> { RevocationCache(capacity = RevocationCache.HARD_MAXIMUM_CAPACITY + 1) }
        shouldThrow<IllegalArgumentException> { RevocationCache(lifetime = Duration.ZERO) }
        shouldThrow<IllegalArgumentException> { RevocationCache(lifetime = 8.days) }
    }

    test("trust settings are bounded and shown without anchors") {
        val pki = Pki.create()
        shouldThrow<ValidationException> {
            tls(TlsRole.Client, crypto) {
                trust { anchors = List(TrustSettings.HARD_MAXIMUM_ANCHORS + 1) { pki.anchor } }
            }
        }
        val log = TestLog.create(HOST)
        val policy = ctPolicy { minimumOperators = 1 }
        val requirement = TransparencyRequirement(LogList(listOf(log.log)), policy)
        requirement shouldBe TransparencyRequirement(LogList(listOf(log.log)), policy)
        requirement.hashCode() shouldBe TransparencyRequirement(LogList(listOf(log.log)), policy).hashCode()
        (requirement == TransparencyRequirement(LogList(emptyList()), policy)) shouldBe false
        requirement.equals(HOST) shouldBe false
        requirement.toString() shouldContain "TransparencyRequirement"
        val configuration = clientConfiguration(pki) {}
        configuration.trust.toString() shouldContain "anchors=1"
        configuration.trust.revocation shouldBe RevocationMode.SoftFail
    }

    test("a trust manager checks only its side, reads hosts from the session and records the peer") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val client = pki.identity(CertificateProfile.TlsClient)
        val clientManager = TlsContext(clientConfiguration(pki)).trustManager
        val serverChain = arrayOf(JcaCertificates.toJca(identity.certificate))
        val hosted = StubSession(staples = emptyList(), host = HOST)
        clientManager.checkServerTrusted(serverChain, AUTH_TYPE, StubEngine(hosted))
        PeerIdentity.of(hosted).shouldNotBeNull()
        val elsewhere = StubSession(staples = emptyList(), host = OTHER_HOST)
        val nowhere = StubSession(staples = emptyList())
        refuses { clientManager.checkServerTrusted(serverChain, AUTH_TYPE, StubEngine(nowhere)) }
        refuses { clientManager.checkServerTrusted(serverChain, AUTH_TYPE, StubEngine(elsewhere)) }
        refuses { clientManager.checkServerTrusted(serverChain, AUTH_TYPE, null as Socket?) }
        refuses { clientManager.checkClientTrusted(serverChain, AUTH_TYPE, null as Socket?) }
        refuses { clientManager.checkClientTrusted(serverChain, AUTH_TYPE, null as SSLEngine?) }
        clientManager.acceptedIssuers.single() shouldBe JcaCertificates.toJca(pki.certificate)
        clientManager.toString() shouldContain "Server"
        shouldThrow<IllegalArgumentException> {
            clientManager.rotate(List(TrustSettings.HARD_MAXIMUM_ANCHORS + 1) { pki.anchor })
        }
        val serverManager = TlsContext(
            serverConfiguration(pki, listOf(identity), mutual(ClientAuthentication.Required)),
        ).trustManager
        val clientChain = arrayOf(JcaCertificates.toJca(client.certificate))
        serverManager.checkClientTrusted(clientChain, AUTH_TYPE)
        serverManager.checkClientTrusted(clientChain, AUTH_TYPE, null as Socket?)
        refuses { serverManager.checkServerTrusted(clientChain, AUTH_TYPE, null as SSLEngine?) }
    }

    test("the anchors of the JDK count together with those of the application when both are asked for") {
        val pki = Pki.create()
        val both = TlsContext(
            tls(TlsRole.Client, crypto) {
                trust {
                    anchors = listOf(pki.anchor)
                    isSystemIncluded = true
                }
            },
        ).trustManager
        both.anchors.size shouldBeGreaterThan 1
        both.anchors shouldContain pki.anchor
        both.rotate(emptyList())
        both.anchors.size shouldBeGreaterThan 0
    }
})
