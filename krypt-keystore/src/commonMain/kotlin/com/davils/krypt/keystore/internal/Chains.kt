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

package com.davils.krypt.keystore.internal

import com.davils.krypt.x509.Certificate

internal object Chains {
    fun of(leaf: Certificate, certificates: List<Certificate>): List<Certificate> {
        val chain = mutableListOf(leaf)
        var next = issuerOf(certificate = leaf, certificates = certificates, used = chain)
        while (next != null) {
            chain += next
            next = issuerOf(certificate = next, certificates = certificates, used = chain)
        }
        return chain
    }

    private fun issuerOf(
        certificate: Certificate,
        certificates: List<Certificate>,
        used: List<Certificate>,
    ): Certificate? = certificates.firstOrNull { candidate ->
        !certificate.isSelfIssued && candidate.subject == certificate.issuer && candidate !in used
    }
}
