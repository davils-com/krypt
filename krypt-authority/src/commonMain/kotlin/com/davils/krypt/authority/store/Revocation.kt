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

package com.davils.krypt.authority.store

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.x509.RevocationReason
import kotlin.time.Instant

/**
 * The revocation of a certificate.
 *
 * @property serialNumber the serial number of the certificate.
 * @property revokedAt when the authority revoked it.
 * @property reason why, or null for no reason given.
 * @property invalidAt since when the key is known or suspected to be compromised, or null.
 * @constructor Creates the revocation.
 * @since 1.0.0
 */
public class Revocation(
    public val serialNumber: DerInteger,
    public val revokedAt: Instant,
    public val reason: RevocationReason? = null,
    public val invalidAt: Instant? = null,
) {
    /**
     * Compares every field.
     *
     * @param other the other object.
     * @return true if [other] is the same revocation.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is Revocation &&
        listOf(serialNumber, revokedAt, reason, invalidAt) ==
        listOf(other.serialNumber, other.revokedAt, other.reason, other.invalidAt)

    /**
     * Hashes the serial number.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = serialNumber.hashCode()

    /**
     * Shows every field.
     *
     * @return the revocation as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Revocation($serialNumber, at=$revokedAt, reason=${reason ?: "none"})"
}
