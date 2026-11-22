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

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.kore.core.dsl.ValidatingBuilder
import com.davils.krypt.core.provider
import com.davils.krypt.keystore.Identity
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.tls.peer.PeerAuthorizer
import com.davils.krypt.tls.trust.TrustSettings
import com.davils.krypt.tls.trust.TrustSettingsBuilder
import java.security.Provider
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours

private const val DEFAULT_SESSIONS: Int = 1_024
private const val DEFAULT_TIMEOUT_HOURS: Int = 24
private const val SSL_CONTEXT: String = "SSLContext"
private const val TLS_13: String = "TLSv1.3"

/**
 * Builds a [TlsConfiguration]: TLS 1.3 only, every cipher suite, group and signature scheme krypt knows before the
 * crypto policy narrows them, host name verification for a client, no client authentication, a session cache of 1024
 * sessions for 24 hours and the JSSE provider of the environment if it offers TLS 1.3, else the default of the JDK.
 *
 * @property role the side the configuration is for.
 * @property crypto the primitives and their environment.
 * @since 1.0.0
 */
@DavilsDsl
public class TlsConfigurationBuilder internal constructor(public val role: TlsRole, public val crypto: Crypto) :
    ValidatingBuilder<TlsConfiguration>() {
    override val subject: String get() = "tls"

    internal var trust: TrustSettings? = null

    /**
     * Whether TLS 1.2 is offered next to TLS 1.3, with the forward secret AEAD suites of [CipherSuite] only.
     *
     * @since 1.0.0
     */
    public var isTls12Enabled: Boolean = false
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * The cipher suites the application allows, in its order of preference; see [TlsConfiguration.cipherSuites].
     *
     * @since 1.0.0
     */
    public var cipherSuites: List<CipherSuite> = CipherSuite.entries
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * The groups the application allows, in its order of preference; see [TlsConfiguration.namedGroups].
     *
     * @since 1.0.0
     */
    public var namedGroups: List<NamedGroup> = NamedGroup.entries
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * The signature schemes the application allows, in its order of preference; see
     * [TlsConfiguration.signatureSchemes].
     *
     * @since 1.0.0
     */
    public var signatureSchemes: List<SignatureScheme> = SignatureScheme.entries
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TlsConfiguration.applicationProtocols].
     *
     * @since 1.0.0
     */
    public var applicationProtocols: List<String> = emptyList()
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TlsConfiguration.serverName].
     *
     * @since 1.0.0
     */
    public var serverName: String? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TlsConfiguration.isHostnameVerified].
     *
     * @since 1.0.0
     */
    public var isHostnameVerified: Boolean = true
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TlsConfiguration.clientAuthentication].
     *
     * @since 1.0.0
     */
    public var clientAuthentication: ClientAuthentication = ClientAuthentication.None
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TlsConfiguration.identities].
     *
     * @since 1.0.0
     */
    public var identities: List<Identity> = emptyList()
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TlsConfiguration.authorizer].
     *
     * @since 1.0.0
     */
    public var authorizer: PeerAuthorizer? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TlsConfiguration.sessionCacheSize].
     *
     * @since 1.0.0
     */
    public var sessionCacheSize: Int = DEFAULT_SESSIONS
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TlsConfiguration.sessionTimeout].
     *
     * @since 1.0.0
     */
    public var sessionTimeout: Duration = DEFAULT_TIMEOUT_HOURS.hours
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TlsConfiguration.provider].
     *
     * @since 1.0.0
     */
    public var provider: Provider? = crypto.environment.provider?.takeIf { found ->
        found.getService(SSL_CONTEXT, TLS_13) != null
    }
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * Configures whom the peer must chain to; see [TrustSettings].
     *
     * @param configure the trust.
     * @since 1.0.0
     */
    public fun trust(configure: TrustSettingsBuilder.() -> Unit) {
        trust = nested(TrustSettingsBuilder(), ::trust, configure)
    }

    override fun assemble(): TlsConfiguration = TlsConfiguration(this)
}
