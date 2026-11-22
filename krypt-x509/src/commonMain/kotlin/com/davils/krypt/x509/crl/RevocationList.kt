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
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.x509.extension.Extensions
import com.davils.krypt.x509.internal.CrlParts
import com.davils.krypt.x509.name.DistinguishedName
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * A certificate revocation list of version 2 by RFC 5280.
 *
 * Looking up a serial number takes logarithmic time: the entries are sorted when the list is read.
 *
 * @property signature the signature.
 * @since 1.0.0
 */
public class RevocationList internal constructor(parts: CrlParts, public val signature: ByteString) {
    /**
     * The DER encoding.
     *
     * @since 1.0.0
     */
    public val encoded: ByteString = parts.encoded

    /**
     * The algorithm of the signature, or null if krypt does not know it.
     *
     * @since 1.0.0
     */
    public val signatureAlgorithm: SignatureAlgorithm? = parts.signatureAlgorithm

    /**
     * The name of the issuer.
     *
     * @since 1.0.0
     */
    public val issuer: DistinguishedName = parts.issuer

    /**
     * When the list was issued.
     *
     * @since 1.0.0
     */
    public val thisUpdate: Instant = parts.thisUpdate

    /**
     * When the next list is due, or null.
     *
     * @since 1.0.0
     */
    public val nextUpdate: Instant? = parts.nextUpdate

    /**
     * The number of the list, or null.
     *
     * @since 1.0.0
     */
    public val number: DerInteger? = parts.number

    /**
     * The number of the full list a delta list builds on, or null for a full list.
     *
     * @since 1.0.0
     */
    public val deltaOf: DerInteger? = parts.deltaOf

    /**
     * The scope of the list, or null for every certificate of the issuer.
     *
     * @since 1.0.0
     */
    public val issuingDistributionPoint: IssuingDistributionPoint? = parts.issuingDistributionPoint

    /**
     * The extensions of the list.
     *
     * @since 1.0.0
     */
    public val extensions: Extensions = parts.extensions

    /**
     * The identifiers of the critical extensions of the list and of its entries that krypt does not know; RFC 5280
     * forbids using a list with one of them, so [com.davils.krypt.x509.path.CrlRevocationChecker] ignores it.
     *
     * @since 1.0.0
     */
    public val unknownCritical: List<ObjectIdentifier> = parts.unknownCritical

    /**
     * The revoked certificates, sorted by serial number.
     *
     * @since 1.0.0
     */
    public val entries: List<RevokedCertificate> = parts.entries

    /**
     * The DER encoding of the part that is signed.
     *
     * @since 1.0.0
     */
    public val tbs: ByteString = parts.tbs

    /**
     * Whether the list is a delta list.
     *
     * @since 1.0.0
     */
    public val isDelta: Boolean get() = deltaOf != null

    /**
     * Returns the entry of [serialNumber].
     *
     * @param serialNumber the serial number.
     * @return the entry, or null if the list does not name the certificate.
     * @since 1.0.0
     */
    public fun find(serialNumber: DerInteger): RevokedCertificate? {
        val index = entries.binarySearch { entry -> entry.serialNumber.compareTo(serialNumber) }
        return entries.getOrNull(index)
    }

    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] is the same list.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is RevocationList && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the issuer, the number and the times.
     *
     * @return the list as text.
     * @since 1.0.0
     */
    override fun toString(): String = "RevocationList(issuer=$issuer, number=${number ?: "none"}, " +
        "thisUpdate=$thisUpdate, nextUpdate=${nextUpdate ?: "none"}, entries=${entries.size})"
}
