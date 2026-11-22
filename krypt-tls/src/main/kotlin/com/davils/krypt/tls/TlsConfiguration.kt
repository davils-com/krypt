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

import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.kore.core.validation.atMost
import com.davils.kore.core.validation.inRange
import com.davils.kore.core.validation.notEmpty
import com.davils.kore.core.validation.validateOrThrow
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.keystore.Identity
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.tls.internal.HostNames
import com.davils.krypt.tls.peer.PeerAuthorizer
import com.davils.krypt.tls.trust.TrustSettings
import com.davils.krypt.tls.trust.TrustSettingsBuilder
import java.security.Provider
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

private const val SUBJECT: String = "tls"
private const val MAXIMUM_PROTOCOL_BYTES: Int = 255

/**
 * The immutable configuration of a TLS client or server, built by [tls] and turned into JSSE objects by [TlsContext].
 *
 * The cipher suites, named groups and signature schemes are the allowlists of the builder narrowed to what the crypto
 * policy of the environment permits, in the order of preference of krypt; TLS 1.3 is the only version unless TLS 1.2
 * was enabled. What the JSSE provider does not offer is left out when the [TlsContext] is created, which reports it in
 * its [TlsCapabilities].
 *
 * @since 1.0.0
 */
public class TlsConfiguration internal constructor(builder: TlsConfigurationBuilder) : Validatable {
    /**
     * The side this configuration is for.
     *
     * @since 1.0.0
     */
    public val role: TlsRole = builder.role

    /**
     * The primitives, whose environment gives the crypto policy, the clock, the randomness and the events.
     *
     * @since 1.0.0
     */
    public val crypto: Crypto = builder.crypto

    /**
     * The versions offered, TLS 1.3 first.
     *
     * @since 1.0.0
     */
    public val versions: List<TlsVersion> = listOfNotNull(
        TlsVersion.Tls13,
        TlsVersion.Tls12.takeIf { builder.isTls12Enabled },
    )

    /**
     * The cipher suites offered, in the order of preference.
     *
     * @since 1.0.0
     */
    public val cipherSuites: List<CipherSuite> = builder.cipherSuites.distinct().filter { suite ->
        val isPermitted = crypto.environment.policy.permits(suite.aead, AlgorithmUse.Protect)
        isPermitted && suite.version in versions
    }

    /**
     * The groups of the key exchange offered, in the order of preference.
     *
     * @since 1.0.0
     */
    public val namedGroups: List<NamedGroup> = builder.namedGroups.distinct().filter { group ->
        crypto.environment.policy.permits(group.algorithm, AlgorithmUse.Protect)
    }

    /**
     * The signature schemes offered and accepted, in the order of preference.
     *
     * @since 1.0.0
     */
    public val signatureSchemes: List<SignatureScheme> = builder.signatureSchemes.distinct().filter { scheme ->
        crypto.environment.policy.permits(scheme.algorithm, AlgorithmUse.Verify)
    }

    /**
     * The application protocols of ALPN (RFC 7301), in the order of preference; empty for no ALPN.
     *
     * @since 1.0.0
     */
    public val applicationProtocols: List<String> = builder.applicationProtocols.toList()

    /**
     * For a client, the host name it sends by server name indication and expects in the certificate of the server,
     * or null to take the host an engine or socket is created for.
     *
     * @since 1.0.0
     */
    public val serverName: String? = builder.serverName

    /**
     * Whether a client checks that the certificate of the server names the host, by RFC 9525.
     *
     * @since 1.0.0
     */
    public val isHostnameVerified: Boolean = builder.isHostnameVerified

    /**
     * Whether a server asks its clients for a certificate.
     *
     * @since 1.0.0
     */
    public val clientAuthentication: ClientAuthentication = builder.clientAuthentication

    /**
     * The identities offered, the default first.
     *
     * @since 1.0.0
     */
    public val identities: List<Identity> = builder.identities.toList()

    /**
     * Whom the peer must chain to and what else it must show.
     *
     * @since 1.0.0
     */
    public val trust: TrustSettings = builder.trust ?: TrustSettingsBuilder().build()

    /**
     * Decides whether a validated peer may connect, or null to admit every validated peer.
     *
     * @since 1.0.0
     */
    public val authorizer: PeerAuthorizer? = builder.authorizer

    /**
     * The most sessions JSSE keeps for resumption.
     *
     * @since 1.0.0
     */
    public val sessionCacheSize: Int = builder.sessionCacheSize

    /**
     * How long a session can be resumed. A resumed session is not checked again, so this bounds how long a peer
     * outlives a change of trust or authorization through resumption.
     *
     * @since 1.0.0
     */
    public val sessionTimeout: Duration = builder.sessionTimeout

    /**
     * The JSSE provider, or null for the default of the JDK.
     *
     * @since 1.0.0
     */
    public val provider: Provider? = builder.provider

    init {
        validateOrThrow(SUBJECT)
    }

    override fun ValidationScope.validate() {
        notEmpty(property = ::cipherSuites, items = cipherSuites)
        notEmpty(property = ::namedGroups, items = namedGroups)
        notEmpty(property = ::signatureSchemes, items = signatureSchemes)
        atMost(property = ::applicationProtocols, value = applicationProtocols.size, maximum = HARD_MAXIMUM_PROTOCOLS)
        each(::applicationProtocols, applicationProtocols) { protocol ->
            val size = protocol.encodeToByteArray().size
            if (size !in 1..MAXIMUM_PROTOCOL_BYTES) fail("A protocol has 1 to $MAXIMUM_PROTOCOL_BYTES bytes")
        }
        val name = serverName
        if (name != null && !HostNames.isHost(name)) fail(::serverName, "A server name is a DNS name or an address")
        atMost(property = ::identities, value = identities.size, maximum = HARD_MAXIMUM_IDENTITIES)
        inRange(property = ::sessionCacheSize, value = sessionCacheSize, range = 1..HARD_MAXIMUM_SESSIONS)
        inRange(property = ::sessionTimeout, value = sessionTimeout, range = 1.seconds..HARD_MAXIMUM_SESSION_TIMEOUT)
        validateRole()
    }

    /**
     * Shows the settings without key material.
     *
     * @return the configuration as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "TlsConfiguration($role, versions=$versions, cipherSuites=${cipherSuites.size}, " +
            "namedGroups=${namedGroups.size}, signatureSchemes=${signatureSchemes.size}, " +
            "alpn=${applicationProtocols.size}, identities=${identities.size}, " +
            "clientAuthentication=$clientAuthentication, $trust)"

    private fun ValidationScope.validateRole() {
        val isServer = role == TlsRole.Server
        if (isServer && identities.isEmpty()) fail(::identities, "A server offers at least one identity")
        val isClientAsking = !isServer && clientAuthentication != ClientAuthentication.None
        if (isClientAsking) fail(::clientAuthentication, "Only a server authenticates clients")
        val isChecking = !isServer || clientAuthentication != ClientAuthentication.None
        val hasAnchors = trust.anchors.isNotEmpty() || trust.isSystemIncluded
        if (isChecking && !hasAnchors) fail(::trust, "A side that checks its peer trusts at least one anchor")
    }

    /**
     * The bounds of a configuration.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The most application protocols.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_PROTOCOLS: Int = 32

        /**
         * The most identities.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_IDENTITIES: Int = 64

        /**
         * The most sessions kept for resumption.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_SESSIONS: Int = 1_000_000

        /**
         * The longest time a session can be resumed: seven days, the longest lifetime of a ticket in TLS 1.3.
         *
         * @since 1.0.0
         */
        public val HARD_MAXIMUM_SESSION_TIMEOUT: Duration = 7.days
    }
}
