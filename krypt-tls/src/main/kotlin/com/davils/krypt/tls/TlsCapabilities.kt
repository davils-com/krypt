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

import com.davils.krypt.tls.internal.Jsse
import java.security.Provider
import javax.net.ssl.SSLContext

/**
 * What the JSSE provider of the running JDK offers of what krypt knows, detected at runtime.
 *
 * JSSE does not report the signature schemes it supports, so they are not part of the capabilities; a scheme it does
 * not know is ignored when it is configured.
 *
 * @param versions the versions offered.
 * @param cipherSuites the cipher suites offered.
 * @param namedGroups the groups offered.
 * @since 1.0.0
 */
public class TlsCapabilities internal constructor(
    versions: List<TlsVersion>,
    cipherSuites: List<CipherSuite>,
    namedGroups: List<NamedGroup>,
) {
    /**
     * The versions the provider offers.
     *
     * @since 1.0.0
     */
    public val versions: List<TlsVersion> = versions.toList()

    /**
     * The cipher suites the provider offers.
     *
     * @since 1.0.0
     */
    public val cipherSuites: List<CipherSuite> = cipherSuites.toList()

    /**
     * The groups the provider offers.
     *
     * @since 1.0.0
     */
    public val namedGroups: List<NamedGroup> = namedGroups.toList()

    /**
     * Whether the provider offers the hybrid post-quantum key exchange [NamedGroup.X25519MlKem768].
     *
     * @since 1.0.0
     */
    public val isHybridKeyExchangeAvailable: Boolean get() = NamedGroup.X25519MlKem768 in namedGroups

    private val values: List<Any?> get() = listOf(versions, cipherSuites, namedGroups)

    /**
     * Compares what is offered.
     *
     * @param other the other object.
     * @return true if [other] offers the same.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is TlsCapabilities && values == other.values

    /**
     * Hashes what is offered.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows what is offered.
     *
     * @return the capabilities as text.
     * @since 1.0.0
     */
    override fun toString(): String = "TlsCapabilities(versions=$versions, cipherSuites=$cipherSuites, " +
        "namedGroups=$namedGroups)"

    /**
     * Detecting capabilities.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Detects what [provider] offers, with a context that holds no keys and trusts nobody.
         *
         * @param provider the JSSE provider, or null for the default of the JDK.
         * @return the capabilities.
         * @throws java.security.NoSuchAlgorithmException if the provider offers no TLS.
         * @since 1.0.0
         */
        public fun of(provider: Provider? = null): TlsCapabilities {
            val context = Jsse.context(provider)
            context.init(emptyArray(), emptyArray(), null)
            return of(context)
        }

        internal fun of(context: SSLContext): TlsCapabilities {
            val supported = context.supportedSSLParameters
            val protocols = supported.protocols.toSet()
            val suites = supported.cipherSuites.toSet()
            val groups = supported.namedGroups.orEmpty().toSet()
            return TlsCapabilities(
                versions = TlsVersion.entries.filter { version -> version.protocolName in protocols },
                cipherSuites = CipherSuite.entries.filter { suite -> suite.suiteName in suites },
                namedGroups = NamedGroup.entries.filter { group -> group.groupName in groups },
            )
        }
    }
}
