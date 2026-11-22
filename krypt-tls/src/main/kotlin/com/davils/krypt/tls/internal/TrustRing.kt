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

import com.davils.krypt.x509.path.TrustAnchor
import java.security.cert.X509Certificate

internal data class TrustRing(
    val application: List<TrustAnchor>,
    val anchors: List<TrustAnchor>,
    val issuers: List<X509Certificate>,
) {
    companion object {
        fun of(application: List<TrustAnchor>, system: List<TrustAnchor>): TrustRing {
            val anchors = application + system
            val certificates = anchors.mapNotNull { anchor -> anchor.certificate }
            return TrustRing(
                application = application.toList(),
                anchors = anchors,
                issuers = certificates.map { certificate -> JcaCertificates.toJca(certificate) },
            )
        }
    }
}
