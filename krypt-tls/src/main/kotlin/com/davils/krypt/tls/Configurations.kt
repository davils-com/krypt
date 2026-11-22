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

import com.davils.krypt.primitive.Crypto

/**
 * Builds the configuration of a TLS client or server.
 *
 * ```
 * val server = tls(TlsRole.Server, crypto) {
 *     identities = listOf(identity)
 *     clientAuthentication = ClientAuthentication.Required
 *     trust { anchors = listOf(anchor) }
 *     authorizer = peerPolicy { uriPrefix("spiffe://example.org/") }
 * }
 * ```
 *
 * @param role the side.
 * @param crypto the primitives, whose environment gives the crypto policy.
 * @param configure the settings.
 * @return the configuration.
 * @throws com.davils.kore.core.validation.report.ValidationException if the policy leaves no cipher suite, group or
 *   signature scheme, an application protocol is empty or longer than 255 bytes, the server name is no host, a bound
 *   is exceeded, a server has no identity, a client asks for client authentication, or a side that checks its peer
 *   has no anchor.
 * @since 1.0.0
 */
public fun tls(role: TlsRole, crypto: Crypto, configure: TlsConfigurationBuilder.() -> Unit): TlsConfiguration {
    val builder = TlsConfigurationBuilder(role, crypto)
    builder.configure()
    return builder.build()
}
