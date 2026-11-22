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
import com.davils.krypt.tls.fixture.FOREIGN_ID
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.SPIFFE_DOMAIN
import com.davils.krypt.tls.fixture.SPIFFE_ID
import com.davils.krypt.tls.fixture.clientConfiguration
import com.davils.krypt.tls.fixture.connect
import com.davils.krypt.tls.fixture.mutual
import com.davils.krypt.tls.fixture.serverConfiguration
import com.davils.krypt.tls.peer.PeerIdentity
import com.davils.krypt.tls.peer.peerPolicy
import com.davils.krypt.tls.trust.TrustFailure
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.name.GeneralName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

private fun failureOf(connection: Connection): TrustFailure? =
    connection.failures.firstNotNullOfOrNull { failure -> TrustFailure.of(failure) }

class MutualTlsTest : FunSpec({
    test("a server that requires a client certificate accepts a client of its authority and records it") {
        val pki = Pki.create()
        val server = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val client = pki.identity(CertificateProfile.TlsClient, GeneralName.Uri(SPIFFE_ID))
        val serverContext = TlsContext(
            serverConfiguration(pki, listOf(server), mutual(ClientAuthentication.Required)),
        )
        val clientContext = TlsContext(clientConfiguration(pki) { identities = listOf(client) })
        val connection = connect(client = clientContext, server = serverContext)
        connection.isEstablished shouldBe true
        val peer = PeerIdentity.of(connection.server.session).shouldNotBeNull()
        peer.certificate shouldBe client.certificate
        peer.uris shouldBe listOf(SPIFFE_ID)
        peer.purposes shouldBe listOf(KeyPurposes.ClientAuth)
    }

    test("a server that requires a client certificate refuses a client without one") {
        val pki = Pki.create()
        val server = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val serverContext = TlsContext(
            serverConfiguration(pki, listOf(server), mutual(ClientAuthentication.Required)),
        )
        val connection = connect(client = TlsContext(clientConfiguration(pki)), server = serverContext)
        connection.isEstablished shouldBe false
    }

    test("a server that requests a client certificate accepts a client without one") {
        val pki = Pki.create()
        val server = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val serverContext = TlsContext(
            serverConfiguration(pki, listOf(server), mutual(ClientAuthentication.Requested)),
        )
        val connection = connect(client = TlsContext(clientConfiguration(pki)), server = serverContext)
        connection.isEstablished shouldBe true
        PeerIdentity.of(connection.server.session).shouldBeNull()
    }

    test("a server refuses a client of a foreign authority") {
        val pki = Pki.create()
        val foreign = Pki.create("Foreign")
        val server = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val client = foreign.identity(CertificateProfile.TlsClient)
        val serverContext = TlsContext(
            serverConfiguration(pki, listOf(server), mutual(ClientAuthentication.Requested)),
        )
        val clientContext = TlsContext(clientConfiguration(pki) { identities = listOf(client) })
        val connection = connect(client = clientContext, server = serverContext)
        connection.isEstablished shouldBe false
        failureOf(connection) shouldBe TrustFailure.NoTrustedPath
    }

    test("a server refuses a client whose certificate does not allow client authentication") {
        val pki = Pki.create()
        val server = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val client = pki.identity(CertificateProfile.TlsServer, GeneralName.Dns("client.example"))
        val serverContext = TlsContext(
            serverConfiguration(pki, listOf(server), mutual(ClientAuthentication.Required)),
        )
        val clientContext = TlsContext(clientConfiguration(pki) { identities = listOf(client) })
        failureOf(connect(client = clientContext, server = serverContext)) shouldBe TrustFailure.Purpose
    }

    test("the peer policy admits a SPIFFE id of its trust domain and refuses one of another") {
        val pki = Pki.create()
        val server = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val serverContext = TlsContext(
            serverConfiguration(pki, listOf(server)) {
                clientAuthentication = ClientAuthentication.Required
                authorizer = peerPolicy {
                    uriPrefix(SPIFFE_DOMAIN)
                    purpose(KeyPurposes.ClientAuth)
                }
            },
        )
        val admitted = pki.identity(CertificateProfile.TlsClient, GeneralName.Uri(SPIFFE_ID))
        val refused = pki.identity(CertificateProfile.TlsClient, GeneralName.Uri(FOREIGN_ID))
        val admittedClient = TlsContext(clientConfiguration(pki) { identities = listOf(admitted) })
        val good = connect(client = admittedClient, server = serverContext)
        good.isEstablished shouldBe true
        val refusedClient = TlsContext(clientConfiguration(pki) { identities = listOf(refused) })
        val bad = connect(client = refusedClient, server = serverContext)
        failureOf(bad) shouldBe TrustFailure.Unauthorized
    }
})
