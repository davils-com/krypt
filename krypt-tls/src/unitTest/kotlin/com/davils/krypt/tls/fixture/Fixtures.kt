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

package com.davils.krypt.tls.fixture

import com.davils.krypt.keystore.Identity
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.tls.ClientAuthentication
import com.davils.krypt.tls.TlsConfiguration
import com.davils.krypt.tls.TlsConfigurationBuilder
import com.davils.krypt.tls.TlsContext
import com.davils.krypt.tls.TlsRole
import com.davils.krypt.tls.tls
import com.davils.krypt.tls.trust.TrustSettingsBuilder
import com.davils.krypt.x509.name.GeneralName

internal const val ROOT: String = "Root"
internal const val LEAF: String = "leaf"
internal const val INTERMEDIATE: String = "Intermediate"
internal const val INTERMEDIATE_DAYS: Int = 45
internal const val DAYS: Int = 30
internal const val HOST: String = "server.example"
internal const val OTHER_HOST: String = "other.example"
internal const val PORT: Int = 443
internal const val SPIFFE_DOMAIN: String = "spiffe://example.org/"
internal const val SPIFFE_ID: String = "spiffe://example.org/ns/prod/sa/api"
internal const val FOREIGN_ID: String = "spiffe://example.com/ns/prod/sa/api"
internal const val H2: String = "h2"
internal const val MESSAGE: String = "hello over TLS"

internal val crypto: Crypto = Crypto()

internal val SERVER_NAME: GeneralName = GeneralName.Dns(HOST)

internal fun serverConfiguration(
    pki: Pki,
    identities: List<Identity>,
    configure: TlsConfigurationBuilder.() -> Unit = {},
): TlsConfiguration = tls(TlsRole.Server, crypto) {
    this.identities = identities
    trust { anchors = listOf(pki.anchor) }
    configure()
}

internal fun clientConfiguration(pki: Pki, configure: TlsConfigurationBuilder.() -> Unit = {}): TlsConfiguration =
    tls(TlsRole.Client, crypto) {
        trust { anchors = listOf(pki.anchor) }
        configure()
    }

internal fun trustingClient(configure: TrustSettingsBuilder.() -> Unit): TlsContext =
    TlsContext(tls(TlsRole.Client, crypto) { trust(configure) })

internal fun connect(client: TlsContext, server: TlsContext, host: String = HOST): Connection {
    val connection = Connection(client = client.createEngine(host), server = server.createEngine())
    return connection.handshake()
}

internal fun mutual(authentication: ClientAuthentication): TlsConfigurationBuilder.() -> Unit = {
    clientAuthentication = authentication
}
