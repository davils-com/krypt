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

package com.davils.krypt.acme.order

import com.davils.krypt.x509.Certificate

/**
 * A certificate chain downloaded as `application/pem-certificate-chain`, by RFC 8555 section 7.4.2.
 *
 * The chain is decoded, not validated: the caller validates it with the path validation of krypt-x509. Values are
 * immutable and safe to share between threads.
 *
 * @property certificates the end-entity certificate first, then the issuers in order.
 * @property alternates the URLs of alternate chains, from `Link` fields with the relation `alternate`.
 * @since 1.0.0
 */
public class CertificateChain internal constructor(
    public val certificates: List<Certificate>,
    public val alternates: List<String>,
) {
    /**
     * The end-entity certificate.
     *
     * @since 1.0.0
     */
    public val leaf: Certificate get() = certificates.first()

    /**
     * Compares the certificates and the alternates.
     *
     * @param other the other object.
     * @return true if [other] is the same chain.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is CertificateChain && certificates == other.certificates && alternates == other.alternates

    /**
     * Hashes the certificates and the alternates.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(certificates, alternates).hashCode()

    /**
     * Shows the sizes.
     *
     * @return the chain as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "CertificateChain(${certificates.size} certificates, ${alternates.size} alternates)"
}
