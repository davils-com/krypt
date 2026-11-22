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
import com.davils.krypt.keystore.Identity
import com.davils.krypt.tls.fixture.HOST
import com.davils.krypt.tls.fixture.MESSAGE
import com.davils.krypt.tls.fixture.PORT
import com.davils.krypt.tls.fixture.PipeSocket
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.clientConfiguration
import com.davils.krypt.tls.fixture.mutual
import com.davils.krypt.tls.fixture.serverConfiguration
import com.davils.krypt.tls.peer.PeerIdentity
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread

private const val ADDRESS: String = "192.0.2.1"
private const val JOIN_MILLIS: Long = 10_000L

private fun exchange(secureClient: SSLSocket, secureServer: SSLSocket, identity: Identity) {
    var received = ""
    val echo = thread {
        val bytes = ByteArray(MESSAGE.length)
        secureServer.inputStream.read(bytes)
        received = bytes.decodeToString()
        secureServer.outputStream.write(bytes)
        secureServer.outputStream.flush()
    }
    secureClient.outputStream.write(MESSAGE.encodeToByteArray())
    secureClient.outputStream.flush()
    val answer = ByteArray(MESSAGE.length)
    secureClient.inputStream.read(answer)
    echo.join(JOIN_MILLIS)
    answer.decodeToString() shouldBe MESSAGE
    received shouldBe MESSAGE
    PeerIdentity.of(secureClient.session).shouldNotBeNull().certificate shouldBe identity.certificate
}

class TlsContextTest : FunSpec({
    test("the parameters carry the configuration, the server name indication and the client authentication") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val client = TlsContext(clientConfiguration(pki))
        val named = client.parameters(HOST)
        named.protocols.toList() shouldContainExactly listOf(TlsVersion.Tls13.protocolName)
        named.serverNames shouldBe listOf(SNIHostName(HOST))
        named.useCipherSuitesOrder shouldBe true
        client.parameters(ADDRESS).serverNames.shouldBeNull()
        client.parameters().serverNames.shouldBeNull()
        val fixed = TlsContext(clientConfiguration(pki) { serverName = "$HOST." })
        fixed.parameters(ADDRESS).serverNames shouldBe listOf(SNIHostName(HOST))
        fixed.createEngine().useClientMode shouldBe true
        val required = TlsContext(serverConfiguration(pki, listOf(identity), mutual(ClientAuthentication.Required)))
        required.parameters(HOST).needClientAuth shouldBe true
        required.parameters(HOST).serverNames.shouldBeNull()
        required.createEngine().useClientMode shouldBe false
        val requested = TlsContext(serverConfiguration(pki, listOf(identity), mutual(ClientAuthentication.Requested)))
        requested.parameters().wantClientAuth shouldBe true
        requested.capabilities.versions shouldContainExactly listOf(TlsVersion.Tls13, TlsVersion.Tls12)
        requested.toString() shouldContain "Server"
    }

    test("the socket factories configure what they create and belong to one side") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val client = TlsContext(clientConfiguration(pki))
        val server = TlsContext(serverConfiguration(pki, listOf(identity)))
        val factory = client.socketFactory()
        factory.defaultCipherSuites.toList() shouldBe client.configuration.cipherSuites.map { suite -> suite.suiteName }
        factory.supportedCipherSuites.isNotEmpty() shouldBe true
        val socket = factory.createSocket() as SSLSocket
        socket.useClientMode shouldBe true
        socket.enabledProtocols.toList() shouldContainExactly listOf(TlsVersion.Tls13.protocolName)
        socket.close()
        val serverFactory = server.serverSocketFactory()
        serverFactory.supportedCipherSuites.isNotEmpty() shouldBe true
        serverFactory.defaultCipherSuites.toList() shouldBe server.parameters().cipherSuites.toList()
        val serverSocket = serverFactory.createServerSocket() as SSLServerSocket
        serverSocket.enabledProtocols.toList() shouldContainExactly listOf(TlsVersion.Tls13.protocolName)
        serverSocket.close()
        shouldThrow<IllegalStateException> { server.socketFactory() }
        shouldThrow<IllegalStateException> { client.serverSocketFactory() }
        PipeSocket.connected { left, right ->
            shouldThrow<IllegalStateException> { server.startTlsClient(left, HOST).use { socket -> socket.isClosed } }
            shouldThrow<IllegalStateException> { client.startTlsServer(right).use { socket -> socket.isClosed } }
        }
    }

    test("STARTTLS upgrades plain sockets the application owns") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val client = TlsContext(clientConfiguration(pki))
        val server = TlsContext(serverConfiguration(pki, listOf(identity)))
        PipeSocket.connected { plainClient, plainServer ->
            server.startTlsServer(plainServer).use { secureServer ->
                client.startTlsClient(plainClient, HOST, PORT).use { secureClient ->
                    exchange(secureClient, secureServer, identity)
                }
            }
            val layered = client.socketFactory().createSocket(plainClient, HOST, PORT, false) as SSLSocket
            layered.sslParameters.serverNames shouldBe listOf(SNIHostName(HOST))
        }
    }
    test("the capabilities of the JDK include the hybrid post-quantum group") {
        val capabilities = TlsCapabilities.of()
        capabilities.isHybridKeyExchangeAvailable shouldBe true
        capabilities.versions shouldContainExactly listOf(TlsVersion.Tls13, TlsVersion.Tls12)
        capabilities.cipherSuites shouldContainExactly CipherSuite.entries
        capabilities shouldBe TlsCapabilities.of(null)
        capabilities.hashCode() shouldBe TlsCapabilities.of().hashCode()
        val reduced = TlsCapabilities(capabilities.versions, capabilities.cipherSuites, listOf(NamedGroup.X25519))
        reduced.isHybridKeyExchangeAvailable shouldBe false
        (reduced == capabilities) shouldBe false
        capabilities.equals(MESSAGE) shouldBe false
        capabilities.toString() shouldContain NamedGroup.X25519MlKem768.name
    }
})
