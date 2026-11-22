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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.tls

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.keystore.Identity
import com.davils.krypt.primitive.secureRandom
import com.davils.krypt.tls.internal.ConfiguredServerSocketFactory
import com.davils.krypt.tls.internal.ConfiguredSocketFactory
import com.davils.krypt.tls.internal.HostNames
import com.davils.krypt.tls.internal.Jsse
import com.davils.krypt.tls.internal.SystemAnchors
import com.davils.krypt.tls.trust.RotatingTrustManager
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.path.TrustAnchor
import java.io.InputStream
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLServerSocketFactory
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * The JSSE objects of a [TlsConfiguration]: an [SSLContext] with the [keyManager] and the [trustManager] of krypt, and
 * the engines, parameters and socket factories configured from it.
 *
 * krypt never opens a socket: the application creates and connects them, through the factories or by itself, and
 * hands an existing plain socket to [startTlsClient] or [startTlsServer] to upgrade it. Identities and anchors are
 * rotated in place by [rotate], without a new context.
 *
 * Safe to share between threads.
 *
 * @property configuration the configuration.
 * @constructor Creates the context.
 * @throws java.security.NoSuchAlgorithmException if the JSSE provider offers no TLS.
 * @throws IllegalStateException if the provider offers none of the configured versions, cipher suites or groups, or
 *   the key of an identity was destroyed.
 * @since 1.0.0
 */
public class TlsContext(public val configuration: TlsConfiguration) {
    private val crypto = configuration.crypto

    private val certificates = Certificates(crypto, configuration.trust.limits)

    private val isClient: Boolean = configuration.role == TlsRole.Client

    /**
     * The key manager, which offers the identities.
     *
     * @since 1.0.0
     */
    public val keyManager: RotatingKeyManager = RotatingKeyManager(crypto, configuration.identities)

    /**
     * The trust manager, which checks the peer.
     *
     * @since 1.0.0
     */
    public val trustManager: RotatingTrustManager = RotatingTrustManager(
        crypto = crypto,
        settings = configuration.trust,
        peer = TlsRole.entries[1 - configuration.role.ordinal],
        serverName = configuration.serverName,
        isHostnameVerified = configuration.isHostnameVerified,
        authorizer = configuration.authorizer,
        systemAnchors = SystemAnchors.load(codec = certificates, isIncluded = configuration.trust.isSystemIncluded),
    )

    /**
     * The context of JSSE.
     *
     * @since 1.0.0
     */
    public val sslContext: SSLContext = Jsse.context(configuration.provider)

    /**
     * What the JSSE provider offers.
     *
     * @since 1.0.0
     */
    public val capabilities: TlsCapabilities

    private val versions: List<TlsVersion>

    private val cipherSuites: List<CipherSuite>

    private val namedGroups: List<NamedGroup>

    init {
        sslContext.init(arrayOf(keyManager), arrayOf(trustManager), crypto.secureRandom())
        capabilities = TlsCapabilities.of(sslContext)
        versions = configuration.versions.filter { version -> version in capabilities.versions }
        cipherSuites = configuration.cipherSuites.filter { suite -> suite in capabilities.cipherSuites }
        namedGroups = configuration.namedGroups.filter { group -> group in capabilities.namedGroups }
        val missing = listOf(versions, cipherSuites, namedGroups).count { offered -> offered.isEmpty() }
        check(missing == 0) { "The JSSE provider offers none of the configured versions, cipher suites or groups" }
        val timeout = configuration.sessionTimeout.inWholeSeconds.toInt()
        listOf(sslContext.clientSessionContext, sslContext.serverSessionContext).forEach { sessions ->
            sessions.sessionCacheSize = configuration.sessionCacheSize
            sessions.sessionTimeout = timeout
        }
    }

    /**
     * Returns the parameters of a new connection: the versions, cipher suites, groups and signature schemes, ALPN, for
     * a client the server name indication of [host] or of [TlsConfiguration.serverName] if it is a DNS name, and for a
     * server the client authentication.
     *
     * @param host the host a client connects to, or null.
     * @return fresh parameters.
     * @since 1.0.0
     */
    public fun parameters(host: String? = null): SSLParameters {
        val parameters = SSLParameters()
        parameters.protocols = versions.map { version -> version.protocolName }.toTypedArray()
        parameters.cipherSuites = cipherSuites.map { suite -> suite.suiteName }.toTypedArray()
        parameters.namedGroups = namedGroups.map { group -> group.groupName }.toTypedArray()
        parameters.signatureSchemes = configuration.signatureSchemes.map { scheme -> scheme.schemeName }.toTypedArray()
        parameters.applicationProtocols = configuration.applicationProtocols.toTypedArray()
        parameters.useCipherSuitesOrder = true
        parameters.needClientAuth = configuration.clientAuthentication == ClientAuthentication.Required
        if (configuration.clientAuthentication == ClientAuthentication.Requested) parameters.wantClientAuth = true
        val name = (configuration.serverName ?: host)?.takeIf { found -> isClient && HostNames.isDnsName(found) }
        if (name != null) parameters.serverNames = listOf(SNIHostName(name.lowercase().removeSuffix(".")))
        return parameters
    }

    /**
     * Creates an engine for one connection, in client mode for a client and in server mode for a server.
     *
     * A client engine created for a [host] and [port] can resume an earlier session with that peer; one created
     * without cannot.
     *
     * @param host the host of the peer, or null.
     * @param port the port of the peer, or -1.
     * @return the engine.
     * @since 1.0.0
     */
    public fun createEngine(host: String? = null, port: Int = -1): SSLEngine {
        val engine = engineFor(host, port)
        engine.useClientMode = isClient
        engine.sslParameters = parameters(host)
        return engine
    }

    /**
     * Returns a factory of client sockets that configures every socket it creates; the application connects them.
     *
     * @return the factory.
     * @throws IllegalStateException if this is the context of a server.
     * @since 1.0.0
     */
    public fun socketFactory(): SSLSocketFactory {
        check(isClient) { "Only a client creates client sockets" }
        return ConfiguredSocketFactory(
            delegate = sslContext.socketFactory,
            suites = cipherSuites.map { suite -> suite.suiteName },
            configure = ::configured,
        )
    }

    /**
     * Returns a factory of server sockets that configures every socket it creates; the application binds them.
     *
     * @return the factory.
     * @throws IllegalStateException if this is the context of a client.
     * @since 1.0.0
     */
    public fun serverSocketFactory(): SSLServerSocketFactory {
        check(!isClient) { "Only a server creates server sockets" }
        return ConfiguredServerSocketFactory(sslContext.serverSocketFactory) { parameters() }
    }

    /**
     * Upgrades a connected plain socket of the application to TLS as a client, such as after STARTTLS. The handshake
     * starts with the first read or write, or with [SSLSocket.startHandshake].
     *
     * @param socket the connected socket, which the application owns.
     * @param host the host of the server, for the server name indication and the host name check.
     * @param port the port of the server.
     * @param autoClose whether closing the TLS socket closes [socket].
     * @return the TLS socket over [socket].
     * @throws IllegalStateException if this is the context of a server.
     * @throws java.io.IOException if [socket] is not connected.
     * @since 1.0.0
     */
    public fun startTlsClient(
        socket: Socket,
        host: String,
        port: Int = socket.port,
        autoClose: Boolean = true,
    ): SSLSocket {
        check(isClient) { "Only a client upgrades as a client" }
        return configured(sslContext.socketFactory.createSocket(socket, host, port, autoClose) as SSLSocket, host)
    }

    /**
     * Upgrades a connected plain socket of the application to TLS as a server, such as after STARTTLS.
     *
     * @param socket the connected socket, which the application owns.
     * @param consumed the bytes the application already read from [socket] that belong to the handshake, or null.
     * @param autoClose whether closing the TLS socket closes [socket].
     * @return the TLS socket over [socket].
     * @throws IllegalStateException if this is the context of a client.
     * @throws java.io.IOException if [socket] is not connected.
     * @since 1.0.0
     */
    public fun startTlsServer(socket: Socket, consumed: InputStream? = null, autoClose: Boolean = true): SSLSocket {
        check(!isClient) { "Only a server upgrades as a server" }
        return configured(sslContext.socketFactory.createSocket(socket, consumed, autoClose) as SSLSocket, null)
    }

    /**
     * Replaces the identities, the anchors or both for every later full handshake and invalidates the sessions JSSE
     * keeps, so they are not resumed. A connection already established keeps working.
     *
     * @param identities the new identities, or null to keep them.
     * @param anchors the new anchors of the application, or null to keep them.
     * @throws IllegalArgumentException if a bound of [TlsConfiguration] or [com.davils.krypt.tls.trust.TrustSettings]
     *   is exceeded.
     * @throws IllegalStateException if the key of an identity was destroyed.
     * @since 1.0.0
     */
    public fun rotate(identities: List<Identity>? = null, anchors: List<TrustAnchor>? = null) {
        identities?.let { found -> keyManager.rotate(found) }
        anchors?.let { found -> trustManager.rotate(found) }
        Jsse.invalidate(sslContext.clientSessionContext)
        Jsse.invalidate(sslContext.serverSessionContext)
    }

    /**
     * Shows the configuration.
     *
     * @return the context as text.
     * @since 1.0.0
     */
    override fun toString(): String = "TlsContext($configuration)"

    private fun engineFor(host: String?, port: Int): SSLEngine {
        if (host == null) return sslContext.createSSLEngine()
        return sslContext.createSSLEngine(host, port)
    }

    private fun configured(socket: SSLSocket, host: String?): SSLSocket {
        socket.useClientMode = isClient
        socket.sslParameters = parameters(host)
        return socket
    }
}
