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

package com.davils.krypt.ocsp

import com.davils.krypt.x509.extension.Extension
import kotlin.time.Instant

/**
 * The answer of a responder about one certificate.
 *
 * @property certId the certificate.
 * @property status its status.
 * @property thisUpdate when the status was known to be correct.
 * @property nextUpdate when newer information will be available, or null.
 * @property extensions the extensions of the entry.
 * @constructor Describes the status of [certId].
 * @since 1.0.0
 */
public class SingleResponse(
    public val certId: CertId,
    public val status: CertificateStatus,
    public val thisUpdate: Instant,
    public val nextUpdate: Instant? = null,
    public val extensions: List<Extension> = emptyList(),
) {
    private val values: List<Any?> get() = listOf(certId, status, thisUpdate, nextUpdate, extensions)

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same answer.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is SingleResponse && values == other.values

    /**
     * Hashes the certificate.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = certId.hashCode()

    /**
     * Shows the certificate, the status and the times.
     *
     * @return the answer as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "SingleResponse($certId, $status, thisUpdate=$thisUpdate, nextUpdate=${nextUpdate ?: NONE})"

    private companion object {
        const val NONE: String = "none"
    }
}
