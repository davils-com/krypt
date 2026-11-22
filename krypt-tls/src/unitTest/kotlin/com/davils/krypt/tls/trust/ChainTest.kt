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
import com.davils.krypt.ocsp.OcspResponseSource
import com.davils.krypt.ocsp.SingleResponse
import com.davils.krypt.tls.TlsContext
import com.davils.krypt.tls.TlsRole
import com.davils.krypt.tls.fixture.HOST
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.StubEngine
import com.davils.krypt.tls.fixture.StubSession
import com.davils.krypt.tls.fixture.TestLog
import com.davils.krypt.tls.fixture.crypto
import com.davils.krypt.tls.fixture.trustingClient
import com.davils.krypt.tls.internal.JcaCertificates
import com.davils.krypt.tls.peer.PeerAuthorizer
import com.davils.krypt.tls.tls
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.path.RevocationListSource
import com.davils.krypt.x509.path.TrustAnchor
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

private const val AUTH_TYPE: String = "ECDHE_ECDSA"
private const val OPERATOR: String = "Operator"

private val OCSP_TIMESTAMPS: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.11129.2.4.5")

private fun check(context: TlsContext, identity: Identity, staples: List<ByteString>) {
    val session = StubSession(staples = staples.map { staple -> staple.toByteArray() }, serverName = HOST)
    val chain = identity.chain.map { certificate -> JcaCertificates.toJca(certificate) }.toTypedArray()
    context.trustManager.checkServerTrusted(chain, AUTH_TYPE, StubEngine(session))
}

private fun refusal(context: TlsContext, identity: Identity, staples: List<ByteString>): TrustFailure =
    shouldThrow<TrustRefusedException> { check(context, identity, staples) }.failure

private suspend fun answer(
    pki: Pki,
    identity: Identity,
    status: CertificateStatus,
    extensions: List<Extension> = emptyList(),
): ByteString {
    val now = crypto.environment.clock.now()
    val single = SingleResponse(
        certId = Ocsp(crypto).certId(identity.certificate, OcspIssuer.of(pki.certificate)),
        status = status,
        thisUpdate = now - 1.minutes,
        nextUpdate = now + 1.days,
        extensions = extensions,
    )
    return pki.responder().sign(listOf(single))
}

class ChainTest : FunSpec({
    test("each certificate of a chain is decided by its staple, else by the sources in order") {
        val root = Pki.create()
        val intermediate = root.intermediate()
        val leaf = intermediate.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val lists = listOf(root.revocationList(), intermediate.revocationList())
        val client = trustingClient {
            anchors = listOf(root.anchor)
            revocation = RevocationMode.HardFail
            ocspSource = OcspResponseSource { request, certificate, _ ->
                val responder = root.responder()
                responder.respond(request).takeIf { certificate == intermediate.certificate }
            }
            revocationListSource = RevocationListSource { lists }
        }
        val leafGood = intermediate.responder().presign(leaf.certificate.serialNumber)
        val intermediateGood = root.responder().presign(intermediate.certificate.serialNumber)
        check(client, leaf, listOf(leafGood, intermediateGood))
        check(client, leaf, listOf(leafGood))
        check(client, leaf, listOf(answer(intermediate, leaf, CertificateStatus.Unknown)))
        check(client, leaf, listOf(ByteString()))
        intermediate.revoke(leaf)
        val revoked = intermediate.responder().presign(leaf.certificate.serialNumber)
        refusal(client, leaf, listOf(revoked, intermediateGood)) shouldBe TrustFailure.Revoked
    }

    test("transparency is checked against the issuer on the path and needs an issuer") {
        val root = Pki.create()
        val intermediate = root.intermediate()
        val leaf = intermediate.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val log = TestLog.create(OPERATOR)
        val logs = LogList(listOf(log.log))
        val policy = ctPolicy {
            minimumForShort = 1
            minimumForLong = 1
            minimumOperators = 1
        }
        val timestamp = log.sign(leaf.certificate, crypto.environment.clock.now() - 1.minutes)
        val value = Transparency(crypto).extension(listOf(timestamp)).value
        val good = answer(
            pki = intermediate,
            identity = leaf,
            status = CertificateStatus.Good,
            extensions = listOf(Extension(OCSP_TIMESTAMPS, false, value)),
        )
        val transparent = trustingClient {
            anchors = listOf(root.anchor)
            transparency(logs, policy)
        }
        check(transparent, leaf, listOf(good))
        val broken = answer(
            pki = intermediate,
            identity = leaf,
            status = CertificateStatus.Good,
            extensions = listOf(Extension(OCSP_TIMESTAMPS, false, ByteString(1, 2))),
        )
        refusal(transparent, leaf, listOf(broken)) shouldBe TrustFailure.TransparencyNotCompliant
        val unchecked = trustingClient {
            anchors = listOf(root.anchor)
            revocation = RevocationMode.Off
            transparency(logs)
        }
        refusal(unchecked, leaf, listOf(good)) shouldBe TrustFailure.TransparencyNotCompliant
        val direct = root.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val bare = TrustAnchor(root.certificate.subject, checkNotNull(root.certificate.publicKey))
        val anonymous = trustingClient {
            anchors = listOf(bare)
            transparency(logs, policy)
        }
        refusal(anonymous, direct, emptyList()) shouldBe TrustFailure.TransparencyNotCompliant
    }

    test("must-staple is not enforced without revocation checking, and a failing authorizer refuses") {
        val pki = Pki.create()
        val identity = pki.custom(listOf(SERVER_NAME)) {
            extendedKeyUsage(listOf(KeyPurposes.ServerAuth))
            mustStaple()
        }
        check(
            trustingClient {
                anchors = listOf(pki.anchor)
                revocation = RevocationMode.Off
            },
            identity,
            emptyList(),
        )
        val broken = TlsContext(
            tls(TlsRole.Client, crypto) {
                trust {
                    anchors = listOf(pki.anchor)
                    isMustStapleEnforced = false
                }
                authorizer = PeerAuthorizer { error("The authorizer broke") }
            },
        )
        refusal(broken, identity, emptyList()) shouldBe TrustFailure.Unauthorized
    }
})
