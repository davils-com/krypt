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

package com.davils.krypt.x509.crl

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.name.GeneralName
import kotlin.time.Instant

/**
 * One entry of a revocation list.
 *
 * @property serialNumber the serial number of the revoked certificate.
 * @property revokedAt when it was revoked.
 * @property reason why it was revoked, or null if no reason is given.
 * @property invalidAt since when the key is known or suspected to be compromised, or null.
 * @property certificateIssuer the issuer of the certificate in an indirect list, or an empty list.
 * @constructor Describes a revoked certificate.
 * @since 1.0.0
 */
public class RevokedCertificate(
    public val serialNumber: DerInteger,
    public val revokedAt: Instant,
    public val reason: RevocationReason? = null,
    public val invalidAt: Instant? = null,
    public val certificateIssuer: List<GeneralName> = emptyList(),
) {
    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same entry.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is RevokedCertificate &&
        listOf(serialNumber, revokedAt, reason, invalidAt, certificateIssuer) ==
        listOf(other.serialNumber, other.revokedAt, other.reason, other.invalidAt, other.certificateIssuer)

    /**
     * Hashes the serial number.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = serialNumber.hashCode()

    /**
     * Shows the serial number, the time and the reason.
     *
     * @return the entry as text.
     * @since 1.0.0
     */
    override fun toString(): String = "RevokedCertificate($serialNumber, at=$revokedAt, reason=${reason ?: "none"})"
}
