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

package com.davils.krypt.tls.internal

import com.davils.kore.core.failure.contained
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.tls.TlsRole
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.path.TrustAnchor
import kotlinx.io.bytestring.ByteString
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

internal class SystemTrust(val anchors: List<TrustAnchor>, private val manager: X509TrustManager?) {
    fun isAccepted(chain: Array<out X509Certificate>, authType: String?, side: TlsRole): Boolean {
        val jdk = manager ?: return false
        val verdict = contained {
            when (side) {
                TlsRole.Client -> jdk.checkClientTrusted(chain, authType)
                TlsRole.Server -> jdk.checkServerTrusted(chain, authType)
            }
            true
        }
        return verdict.getOrNull() == true
    }

    companion object {
        val None: SystemTrust = SystemTrust(anchors = emptyList(), manager = null)

        fun load(codec: Certificates, isIncluded: Boolean): SystemTrust {
            if (!isIncluded) return None
            return of(codec = codec, store = null)
        }

        fun of(codec: Certificates, store: KeyStore?): SystemTrust {
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(store)
            val managers = factory.trustManagers.filterIsInstance<X509TrustManager>()
            val manager = managers.first()
            val roots = manager.acceptedIssuers.toList()
            val decoded = roots.mapNotNull { root -> codec.decode(ByteString(root.encoded)).getOrNull() }
            val anchors = decoded.mapNotNull { root -> contained { TrustAnchor.of(root) }.getOrNull() }
            return SystemTrust(anchors = anchors, manager = manager)
        }
    }
}
