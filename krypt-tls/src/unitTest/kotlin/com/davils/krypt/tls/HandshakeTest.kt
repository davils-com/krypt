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

package com.davils.krypt.tls

import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.tls.fixture.Connection
import com.davils.krypt.tls.fixture.H2
import com.davils.krypt.tls.fixture.HOST
import com.davils.krypt.tls.fixture.MESSAGE
import com.davils.krypt.tls.fixture.OTHER_HOST
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.clientConfiguration
import com.davils.krypt.tls.fixture.connect
import com.davils.krypt.tls.fixture.serverConfiguration
import com.davils.krypt.tls.peer.PeerIdentity
import com.davils.krypt.tls.trust.TrustFailure
import com.davils.krypt.x509.name.GeneralName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

class HandshakeTest : FunSpec({
    test("a client and a server agree on TLS 1.3, ALPN and the identity of the server") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val server = TlsContext(serverConfiguration(pki, listOf(identity)) { applicationProtocols = listOf(H2) })
        val client = TlsContext(clientConfiguration(pki) { applicationProtocols = listOf("http/1.1", H2) })
        val connection = connect(client, server)
        connection.failures shouldBe emptyList()
        connection.isEstablished shouldBe true
        connection.client.session.protocol shouldBe TlsVersion.Tls13.protocolName
        connection.client.applicationProtocol shouldBe H2
        connection.send(MESSAGE) shouldBe MESSAGE
        val peer = PeerIdentity.of(connection.client.session).shouldNotBeNull()
        peer.certificate shouldBe identity.certificate
        peer.anchor shouldBe pki.anchor
        peer.names shouldContain SERVER_NAME
    }

    test("TLS 1.2 is negotiated only by opt-in") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val server = TlsContext(serverConfiguration(pki, listOf(identity)) { isTls12Enabled = true })
        val legacy = TlsContext(clientConfiguration(pki) { isTls12Enabled = true })
        val engine = server.createEngine()
        engine.enabledProtocols = arrayOf(TlsVersion.Tls12.protocolName)
        val opted = Connection(client = legacy.createEngine(HOST), server = engine)
        opted.handshake()
        opted.isEstablished shouldBe true
        opted.client.session.protocol shouldBe TlsVersion.Tls12.protocolName
        val modern = TlsContext(clientConfiguration(pki))
        val refusing = server.createEngine()
        refusing.enabledProtocols = arrayOf(TlsVersion.Tls12.protocolName)
        val refused = Connection(client = modern.createEngine(HOST), server = refusing)
        refused.handshake()
        refused.isEstablished shouldBe false
    }

    test("a client refuses a server whose certificate names another host") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val server = TlsContext(serverConfiguration(pki, listOf(identity)))
        val client = TlsContext(clientConfiguration(pki))
        val connection = connect(client, server, OTHER_HOST)
        connection.isEstablished shouldBe false
        connection.failures.firstNotNullOf { failure -> TrustFailure.of(failure) } shouldBe TrustFailure.HostMismatch
    }

    test("a server chooses the identity the client names by SNI") {
        val pki = Pki.create()
        val first = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val second = pki.identity(CertificateProfile.TlsServer, GeneralName.Dns(OTHER_HOST))
        val server = TlsContext(serverConfiguration(pki, listOf(first, second)))
        val client = TlsContext(clientConfiguration(pki))
        val toOther = connect(client, server, OTHER_HOST)
        toOther.isEstablished shouldBe true
        PeerIdentity.of(toOther.client.session).shouldNotBeNull().certificate shouldBe second.certificate
        val toFirst = connect(client, server, HOST)
        PeerIdentity.of(toFirst.client.session).shouldNotBeNull().certificate shouldBe first.certificate
    }
})
