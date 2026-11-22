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

package com.davils.krypt.tls.peer

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.path.TrustAnchor
import javax.net.ssl.SSLSession

/**
 * The validated identity of a TLS peer: the chain it sent, the path krypt validated and the names of its certificate.
 *
 * The trust manager of krypt records the identity in the session of every handshake it accepts, where [of] reads it.
 * A session that JSSE resumed was not checked again and carries no identity when JSSE restored it from a ticket.
 *
 * @param chain the certificates the peer sent, its own first.
 * @param path the validated path, the certificate of the peer first, the anchor not included.
 * @property anchor the trust anchor the path leads to.
 * @since 1.0.0
 */
public class PeerIdentity internal constructor(
    chain: List<Certificate>,
    path: List<Certificate>,
    public val anchor: TrustAnchor,
) {
    /**
     * The certificates the peer sent, its own first.
     *
     * @since 1.0.0
     */
    public val chain: List<Certificate> = chain.toList()

    /**
     * The validated path, the certificate of the peer first, the anchor not included.
     *
     * @since 1.0.0
     */
    public val path: List<Certificate> = path.toList()

    /**
     * The certificate of the peer.
     *
     * @since 1.0.0
     */
    public val certificate: Certificate get() = path.first()

    /**
     * The subject alternative names of the certificate of the peer.
     *
     * @since 1.0.0
     */
    public val names: List<GeneralName> get() = certificate.extensions.subjectAlternativeNames

    /**
     * The URIs among the [names], such as a SPIFFE id.
     *
     * @since 1.0.0
     */
    public val uris: List<String> get() = names.filterIsInstance<GeneralName.Uri>().map { name -> name.uri }

    /**
     * The extended key usages of the certificate of the peer, empty if it has none.
     *
     * @since 1.0.0
     */
    public val purposes: List<ObjectIdentifier> get() = certificate.extensions.extendedKeyUsage.orEmpty()

    private val values: List<Any?> get() = listOf(chain, path, anchor)

    /**
     * Compares the chain, the path and the anchor.
     *
     * @param other the other object.
     * @return true if [other] is the same identity.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is PeerIdentity && values == other.values

    /**
     * Hashes the path.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the subject and the anchor.
     *
     * @return the identity as text.
     * @since 1.0.0
     */
    override fun toString(): String = "PeerIdentity(${certificate.subject}, $anchor)"

    /**
     * Reading identities from sessions.
     *
     * @since 1.0.0
     */
    public companion object {
        internal const val SESSION_KEY: String = "com.davils.krypt.tls.peer"

        /**
         * Returns the identity krypt recorded when it validated the peer of [session].
         *
         * @param session a session of a handshake krypt checked.
         * @return the identity, or null if krypt validated no certificate for this session.
         * @since 1.0.0
         */
        public fun of(session: SSLSession): PeerIdentity? = session.getValue(SESSION_KEY) as? PeerIdentity
    }
}
