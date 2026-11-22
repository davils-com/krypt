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

package com.davils.krypt.tls.reload

import com.davils.krypt.x509.Certificate
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * The expiry status of a certificate in use.
 *
 * @property certificate the certificate.
 * @property state where it stands.
 * @property remaining the time until it expires, negative once it has.
 * @since 1.0.0
 */
public class CertificateExpiry internal constructor(
    public val certificate: Certificate,
    public val state: ExpiryState,
    public val remaining: Duration,
) {
    private val values: List<Any?> get() = listOf(certificate, state, remaining)

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same status.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CertificateExpiry && values == other.values

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the subject, the state and the remaining time.
     *
     * @return the status as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CertificateExpiry(${certificate.subject}, $state, remaining=$remaining)"

    internal companion object {
        fun of(certificate: Certificate, at: Instant, warning: Duration): CertificateExpiry {
            val remaining = certificate.notAfter - at
            val states = listOf(
                ExpiryState.NotYetValid.takeIf { at < certificate.notBefore },
                ExpiryState.Expired.takeIf { remaining.isNegative() },
                ExpiryState.Expiring.takeIf { remaining <= warning },
            )
            val state = states.firstNotNullOfOrNull { found -> found } ?: ExpiryState.Valid
            return CertificateExpiry(certificate = certificate, state = state, remaining = remaining)
        }
    }
}
