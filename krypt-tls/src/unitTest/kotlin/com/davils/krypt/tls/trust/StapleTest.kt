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

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.ct.LogList
import com.davils.krypt.ct.Transparency
import com.davils.krypt.ct.ctPolicy
import com.davils.krypt.keystore.Identity
import com.davils.krypt.ocsp.CertificateStatus
import com.davils.krypt.ocsp.Ocsp
import com.davils.krypt.ocsp.OcspIssuer
import com.davils.krypt.ocsp.SingleResponse
import com.davils.krypt.tls.TlsContext
import com.davils.krypt.tls.fixture.HOST
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.StubEngine
import com.davils.krypt.tls.fixture.StubSession
import com.davils.krypt.tls.fixture.TestLog
import com.davils.krypt.tls.fixture.clientConfiguration
import com.davils.krypt.tls.fixture.crypto
import com.davils.krypt.tls.fixture.trustingClient
import com.davils.krypt.tls.internal.JcaCertificates
import com.davils.krypt.tls.peer.PeerIdentity
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.KeyPurposes
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

private const val AUTH_TYPE: String = "ECDHE_ECDSA"
private const val OPERATOR: String = "Operator"
private const val GARBAGE: Byte = 0x30

private val OCSP_TIMESTAMPS: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.11129.2.4.5")

private fun check(context: TlsContext, identity: Identity, staples: List<ByteString>): StubSession {
    val session = StubSession(staples = staples.map { staple -> staple.toByteArray() }, serverName = HOST)
    val chain = arrayOf(JcaCertificates.toJca(identity.certificate))
    context.trustManager.checkServerTrusted(chain, AUTH_TYPE, StubEngine(session))
    return session
}

private fun refusal(context: TlsContext, identity: Identity, staples: List<ByteString>): TrustFailure =
    shouldThrow<TrustRefusedException> { check(context, identity, staples) }.failure

private suspend fun stapled(pki: Pki, identity: Identity, extensions: List<Extension>): ByteString {
    val ocsp = Ocsp(crypto)
    val now = crypto.environment.clock.now()
    val single = SingleResponse(
        certId = ocsp.certId(identity.certificate, OcspIssuer.of(pki.certificate)),
        status = CertificateStatus.Good,
        thisUpdate = now - 1.minutes,
        nextUpdate = now + 1.days,
        extensions = extensions,
    )
    return pki.responder().sign(listOf(single))
}

class StapleTest : FunSpec({
    test("a stapled response decides the revocation and satisfies must-staple") {
        val pki = Pki.create()
        val identity = pki.custom(listOf(SERVER_NAME)) {
            extendedKeyUsage(listOf(KeyPurposes.ServerAuth))
            mustStaple()
        }
        val client = TlsContext(clientConfiguration(pki))
        val good = pki.responder().presign(identity.certificate.serialNumber)
        val session = check(client, identity, listOf(good))
        PeerIdentity.of(session).shouldNotBeNull().certificate shouldBe identity.certificate
        refusal(client, identity, listOf(ByteString(GARBAGE))) shouldBe TrustFailure.MustStapleMissing
        refusal(client, identity, emptyList()) shouldBe TrustFailure.MustStapleMissing
        pki.revoke(identity)
        val revoked = pki.responder().presign(identity.certificate.serialNumber)
        refusal(client, identity, listOf(revoked)) shouldBe TrustFailure.Revoked
    }

    test("transparency is satisfied by timestamps in the stapled response and refused without them") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val log = TestLog.create(OPERATOR)
        val transparent = trustingClient {
            anchors = listOf(pki.anchor)
            transparency(
                logs = LogList(listOf(log.log)),
                policy = ctPolicy {
                    minimumForShort = 1
                    minimumForLong = 1
                    minimumOperators = 1
                },
            )
        }
        val timestamp = log.sign(identity.certificate, crypto.environment.clock.now() - 1.minutes)
        val value = Transparency(crypto).extension(listOf(timestamp)).value
        val staple = stapled(pki, identity, listOf(Extension(OCSP_TIMESTAMPS, false, value)))
        check(transparent, identity, listOf(staple))
        refusal(transparent, identity, emptyList()) shouldBe TrustFailure.TransparencyNotCompliant
        refusal(transparent, identity, listOf(stapled(pki, identity, emptyList()))) shouldBe
            TrustFailure.TransparencyNotCompliant
    }

    test("a manager refuses the other side, an empty chain and a chain it cannot read") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val manager = TlsContext(clientConfiguration(pki)).trustManager
        val chain = arrayOf(JcaCertificates.toJca(identity.certificate))
        shouldThrow<TrustRefusedException> { manager.checkClientTrusted(chain, AUTH_TYPE) }.failure shouldBe
            TrustFailure.WrongSide
        shouldThrow<TrustRefusedException> { manager.checkServerTrusted(emptyArray(), AUTH_TYPE) }.failure shouldBe
            TrustFailure.Malformed
        shouldThrow<TrustRefusedException> { manager.checkServerTrusted(null, AUTH_TYPE) }.failure shouldBe
            TrustFailure.Malformed
        shouldThrow<TrustRefusedException> { manager.checkServerTrusted(chain, AUTH_TYPE) }.failure shouldBe
            TrustFailure.HostMismatch
    }
})
