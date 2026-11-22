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
import com.davils.krypt.tls.fixture.HOST
import com.davils.krypt.tls.fixture.MESSAGE
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.clientConfiguration
import com.davils.krypt.tls.fixture.serverConfiguration
import com.davils.krypt.tls.peer.PeerIdentity
import com.davils.krypt.tls.trust.TrustFailure
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

private fun open(client: TlsContext, server: TlsContext): Connection {
    val connection = Connection(client = client.createEngine(), server = server.createEngine())
    return connection.handshake()
}

class RotationTest : FunSpec({
    test("rotated identities serve new handshakes while an established connection keeps working") {
        val pki = Pki.create()
        val old = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val new = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val server = TlsContext(serverConfiguration(pki, listOf(old)))
        val client = TlsContext(clientConfiguration(pki) { serverName = HOST })
        val established = open(client, server)
        PeerIdentity.of(established.client.session).shouldNotBeNull().certificate shouldBe old.certificate
        server.rotate(identities = listOf(new))
        server.keyManager.identities shouldBe listOf(new)
        val fresh = open(client, server)
        PeerIdentity.of(fresh.client.session).shouldNotBeNull().certificate shouldBe new.certificate
        established.send(MESSAGE) shouldBe MESSAGE
    }

    test("rotated anchors decide new handshakes while an established connection keeps working") {
        val pki = Pki.create()
        val other = Pki.create("Other")
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val server = TlsContext(serverConfiguration(pki, listOf(identity)))
        val client = TlsContext(clientConfiguration(pki) { serverName = HOST })
        val established = open(client, server)
        established.isEstablished shouldBe true
        client.rotate(anchors = listOf(other.anchor))
        client.trustManager.anchors shouldBe listOf(other.anchor)
        val refused = open(client, server)
        refused.failures.firstNotNullOf { failure -> TrustFailure.of(failure) } shouldBe TrustFailure.NoTrustedPath
        established.send(MESSAGE) shouldBe MESSAGE
        client.rotate()
        client.trustManager.anchors shouldBe listOf(other.anchor)
    }
})
