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

import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.keystore.Identity
import com.davils.krypt.tls.TlsRole
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.crypto
import com.davils.krypt.tls.internal.JcaCertificates
import com.davils.krypt.tls.internal.SystemTrust
import com.davils.krypt.tls.tls
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.path.TrustAnchor
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

private const val AUTH_TYPE: String = "ECDHE_ECDSA"

private val codec: Certificates = Certificates(crypto)

private fun storeOf(pki: Pki): KeyStore {
    val store = KeyStore.getInstance(KeyStore.getDefaultType())
    store.load(null, null)
    store.setCertificateEntry("root", JcaCertificates.toJca(pki.certificate))
    return store
}

private fun jdkManagerOf(store: KeyStore): X509TrustManager {
    val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    factory.init(store)
    val managers = factory.trustManagers.filterIsInstance<X509TrustManager>()
    return managers.single()
}

private suspend fun distrusting(pki: Pki): SystemTrust =
    SystemTrust(anchors = listOf(pki.anchor), manager = jdkManagerOf(storeOf(Pki.create("Other"))))

private fun managerOf(peer: TlsRole, application: List<TrustAnchor>, system: SystemTrust): RotatingTrustManager {
    val settings = tls(TlsRole.Client, crypto) {
        trust {
            anchors = application
            isSystemIncluded = true
        }
    }.trust
    return RotatingTrustManager(
        crypto = crypto,
        settings = settings,
        peer = peer,
        serverName = null,
        isHostnameVerified = false,
        authorizer = null,
        system = system,
    )
}

private fun chainOf(identity: Identity): Array<X509Certificate> {
    val certificates = identity.chain.map { certificate -> JcaCertificates.toJca(certificate) }
    return certificates.toTypedArray()
}

private fun refusal(check: () -> Unit): TrustFailure = shouldThrow<TrustRefusedException> { check() }.failure

private fun check(manager: RotatingTrustManager, chain: Array<X509Certificate>) {
    when (manager.peer) {
        TlsRole.Client -> manager.checkClientTrusted(chain, AUTH_TYPE)
        TlsRole.Server -> manager.checkServerTrusted(chain, AUTH_TYPE)
    }
}

class SystemAnchorTrustTest : FunSpec({
    test("a path to an anchor of the JDK needs the trust manager of the JDK to accept it as well") {
        val pki = Pki.create()
        val chain = chainOf(pki.identity(CertificateProfile.TlsServer, SERVER_NAME))
        val accepting = SystemTrust.of(codec = codec, store = storeOf(pki))
        accepting.anchors shouldContain pki.anchor
        check(managerOf(TlsRole.Server, application = emptyList(), system = accepting), chain)
        val refused = managerOf(TlsRole.Server, application = emptyList(), system = distrusting(pki))
        refusal { check(refused, chain) } shouldBe TrustFailure.NoTrustedPath
    }

    test("a client certificate chaining to an anchor of the JDK is checked by the JDK for the client side") {
        val pki = Pki.create()
        val identity = pki.custom(listOf(GeneralName.Uri("spiffe://example.org/client"))) {
            extendedKeyUsage(listOf(KeyPurposes.ClientAuth))
        }
        val chain = chainOf(identity)
        val accepting = SystemTrust.of(codec = codec, store = storeOf(pki))
        check(managerOf(TlsRole.Client, application = emptyList(), system = accepting), chain)
        val refused = managerOf(TlsRole.Client, application = emptyList(), system = distrusting(pki))
        refusal { check(refused, chain) } shouldBe TrustFailure.NoTrustedPath
    }

    test("a path to an anchor of the application is validated by krypt alone, even if the JDK holds the anchor too") {
        val pki = Pki.create()
        val chain = chainOf(pki.identity(CertificateProfile.TlsServer, SERVER_NAME))
        val manager = managerOf(TlsRole.Server, application = listOf(pki.anchor), system = distrusting(pki))
        check(manager, chain)
        manager.rotate(emptyList())
        refusal { check(manager, chain) } shouldBe TrustFailure.NoTrustedPath
    }

    test("without the anchors of the JDK nothing is accepted on their behalf") {
        val pki = Pki.create()
        val chain = chainOf(pki.identity(CertificateProfile.TlsServer, SERVER_NAME))
        SystemTrust.None.isAccepted(chain = chain, authType = AUTH_TYPE, side = TlsRole.Server) shouldBe false
    }
})
