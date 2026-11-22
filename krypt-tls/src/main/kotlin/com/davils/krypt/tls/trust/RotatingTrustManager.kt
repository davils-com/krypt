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

@file:OptIn(ExperimentalAtomicApi::class)

package com.davils.krypt.tls.trust

import com.davils.krypt.primitive.Crypto
import com.davils.krypt.tls.TlsRole
import com.davils.krypt.tls.internal.Handshake
import com.davils.krypt.tls.internal.JcaCertificates
import com.davils.krypt.tls.internal.Sessions
import com.davils.krypt.tls.internal.TrustCheck
import com.davils.krypt.tls.internal.TrustRing
import com.davils.krypt.tls.peer.PeerAuthorizer
import com.davils.krypt.tls.peer.PeerIdentity
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.path.TrustAnchor
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import java.net.Socket
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSession
import javax.net.ssl.X509ExtendedTrustManager
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * The trust manager of krypt: it validates the certificates of a TLS peer with the path validation of krypt-x509 by
 * RFC 5280, never with the PKIX of the JDK, against anchors it reads atomically, so [rotate] changes the trust of
 * every later handshake without a new SSLContext.
 *
 * A manager checks one side, the [peer]: a server with the purpose serverAuth, a client with clientAuth, each
 * required in the extended key usage of the peer and of every authority on the path that has one. After the path it
 * checks, in this order, the host name of a server by RFC 9525, the pins, the TLS feature status_request of RFC 7633,
 * the Certificate Transparency and the authorizer; the first refusal ends the handshake with a
 * [TrustRefusedException], whose [TrustFailure] the application reads with [TrustFailure.of]. The identity of an
 * accepted peer is recorded in the session for [PeerIdentity.of].
 *
 * The revocation of every certificate on the path is decided, unless the mode is [RevocationMode.Off], by the OCSP
 * response the peer stapled for it (TLS 1.3 staples one per certificate), the [TrustSettings.cache], the
 * [TrustSettings.ocspSource] and the [TrustSettings.revocationListSource], in this order.
 *
 * JSSE calls a trust manager synchronously, so the suspending checks run in `runBlocking` on the thread of JSSE; the
 * JCA backend of krypt does not really suspend, but a source of the application that does, such as one that fetches
 * a response, blocks the handshake while it waits. krypt starts no thread and opens no connection of its own.
 *
 * Safe to share between threads.
 *
 * @property settings the trust settings.
 * @property peer the side this manager checks.
 * @since 1.0.0
 */
public class RotatingTrustManager internal constructor(
    crypto: Crypto,
    public val settings: TrustSettings,
    public val peer: TlsRole,
    private val serverName: String?,
    private val isHostnameVerified: Boolean,
    authorizer: PeerAuthorizer?,
    private val systemAnchors: List<TrustAnchor>,
) : X509ExtendedTrustManager() {
    private val certificates: Certificates = Certificates(crypto, settings.limits)

    private val purpose = listOf(KeyPurposes.ClientAuth, KeyPurposes.ServerAuth)[peer.ordinal]

    private val trustCheck: TrustCheck = TrustCheck(
        crypto = crypto,
        settings = settings,
        purpose = purpose,
        authorizer = authorizer,
    )

    private val ring = AtomicReference(TrustRing.of(settings.anchors + systemAnchors))

    /**
     * The anchors every new handshake is checked against: those of the application and, if included, those of the
     * JDK.
     *
     * @since 1.0.0
     */
    public val anchors: List<TrustAnchor> get() = ring.load().anchors

    /**
     * Replaces the anchors of the application for every later handshake; the anchors of the JDK stay if they were
     * included. A handshake in progress finishes with the anchors it started with.
     *
     * @param anchors the new anchors of the application.
     * @throws IllegalArgumentException if there are more than [TrustSettings.HARD_MAXIMUM_ANCHORS] anchors.
     * @since 1.0.0
     */
    public fun rotate(anchors: List<TrustAnchor>) {
        require(anchors.size <= TrustSettings.HARD_MAXIMUM_ANCHORS) {
            "At most ${TrustSettings.HARD_MAXIMUM_ANCHORS} anchors are trusted"
        }
        ring.store(TrustRing.of(anchors + systemAnchors))
    }

    @Throws(CertificateException::class)
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        verify(side = TlsRole.Client, chain = chain, session = null)
    }

    @Throws(CertificateException::class)
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
        verify(side = TlsRole.Client, chain = chain, session = Sessions.of(socket))
    }

    @Throws(CertificateException::class)
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
        verify(side = TlsRole.Client, chain = chain, session = Sessions.of(engine))
    }

    @Throws(CertificateException::class)
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        verify(side = TlsRole.Server, chain = chain, session = null)
    }

    @Throws(CertificateException::class)
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
        verify(side = TlsRole.Server, chain = chain, session = Sessions.of(socket))
    }

    @Throws(CertificateException::class)
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
        verify(side = TlsRole.Server, chain = chain, session = Sessions.of(engine))
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = ring.load().issuers.toTypedArray()

    /**
     * Shows the side and the number of anchors.
     *
     * @return the manager as text.
     * @since 1.0.0
     */
    override fun toString(): String = "RotatingTrustManager(peer=$peer, anchors=${anchors.size})"

    private fun verify(side: TlsRole, chain: Array<out X509Certificate>?, session: SSLSession?) {
        if (side != peer) throw TrustRefusedException(TrustFailure.WrongSide)
        val decoded = JcaCertificates.fromJca(certificates, chain)
        val presented = decoded ?: throw TrustRefusedException(TrustFailure.Malformed)
        val handshake = Handshake(
            chain = presented,
            staples = Sessions.staples(session).map { response -> ByteString(response) },
            host = serverName ?: Sessions.requestedHost(session) ?: session?.peerHost,
            isHostVerified = isHostnameVerified && peer == TlsRole.Server,
        )
        val current = ring.load().anchors
        val identity = runBlocking { trustCheck.check(handshake, current) }
        session?.putValue(PeerIdentity.SESSION_KEY, identity)
    }
}
