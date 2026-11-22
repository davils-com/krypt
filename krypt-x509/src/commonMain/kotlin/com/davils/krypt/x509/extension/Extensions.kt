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

package com.davils.krypt.x509.extension

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.internal.ExtensionParts
import com.davils.krypt.x509.internal.ExtensionReader
import com.davils.krypt.x509.internal.ExtensionReads
import com.davils.krypt.x509.internal.ExtensionReads.readAccessDescriptions
import com.davils.krypt.x509.internal.ExtensionReads.readAuthorityKeyIdentifier
import com.davils.krypt.x509.internal.ExtensionReads.readBasicConstraints
import com.davils.krypt.x509.internal.ExtensionReads.readDistributionPoints
import com.davils.krypt.x509.internal.ExtensionReads.readKeyPurposes
import com.davils.krypt.x509.internal.ExtensionReads.readKeyUsage
import com.davils.krypt.x509.internal.ExtensionReads.readNameConstraints
import com.davils.krypt.x509.internal.ExtensionReads.readPolicies
import com.davils.krypt.x509.internal.ExtensionReads.readPolicyConstraints
import com.davils.krypt.x509.internal.ExtensionReads.readPolicyMappings
import com.davils.krypt.x509.internal.ExtensionReads.readSkipCount
import com.davils.krypt.x509.internal.ExtensionReads.readTlsFeatures
import com.davils.krypt.x509.internal.NameCodec.readGeneralNames
import com.davils.krypt.x509.name.GeneralName
import kotlinx.io.bytestring.ByteString

/**
 * The extensions of a certificate, a request or a revocation list: every extension as it is encoded, and the value
 * of every extension krypt knows, read strictly when the structure is read.
 *
 * @property all every extension, in the order of its encoding.
 * @since 1.0.0
 */
public class Extensions private constructor(public val all: List<Extension>, maximumNames: Int) {
    private val reads = ExtensionReader(all)

    /**
     * The basic constraints, or null.
     *
     * @since 1.0.0
     */
    public val basicConstraints: BasicConstraints? = reads.read(
        ExtensionIds.BasicConstraints,
    ) { readBasicConstraints() }

    /**
     * The key usages, or null if the extension is absent.
     *
     * @since 1.0.0
     */
    public val keyUsage: Set<KeyUsage>? = reads.read(ExtensionIds.KeyUsage) { readKeyUsage() }

    /**
     * The key purposes of the extended key usage, or null if the extension is absent.
     *
     * @since 1.0.0
     */
    public val extendedKeyUsage: List<ObjectIdentifier>? =
        reads.read(ExtensionIds.ExtendedKeyUsage) { readKeyPurposes(maximumNames) }

    /**
     * The subject alternative names, or an empty list.
     *
     * @since 1.0.0
     */
    public val subjectAlternativeNames: List<GeneralName> =
        reads.read(ExtensionIds.SubjectAlternativeName) { readGeneralNames(maximumNames) }.orEmpty()

    /**
     * The issuer alternative names, or an empty list.
     *
     * @since 1.0.0
     */
    public val issuerAlternativeNames: List<GeneralName> =
        reads.read(ExtensionIds.IssuerAlternativeName) { readGeneralNames(maximumNames) }.orEmpty()

    /**
     * The subject key identifier, or null.
     *
     * @since 1.0.0
     */
    public val subjectKeyIdentifier: ByteString? = reads.read(ExtensionIds.SubjectKeyIdentifier) { readOctetString() }

    /**
     * The authority key identifier, or null.
     *
     * @since 1.0.0
     */
    public val authorityKeyIdentifier: AuthorityKeyIdentifier? =
        reads.read(ExtensionIds.AuthorityKeyIdentifier) { readAuthorityKeyIdentifier(maximumNames) }

    /**
     * The name constraints, or null.
     *
     * @since 1.0.0
     */
    public val nameConstraints: NameConstraints? =
        reads.read(ExtensionIds.NameConstraints) { readNameConstraints(maximumNames) }

    /**
     * The identifiers of the certificate policies, or null if the extension is absent.
     *
     * @since 1.0.0
     */
    public val certificatePolicies: List<ObjectIdentifier>? =
        reads.read(ExtensionIds.CertificatePolicies) { readPolicies(maximumNames) }

    /**
     * The policy mappings, or an empty list.
     *
     * @since 1.0.0
     */
    public val policyMappings: List<PolicyMapping> =
        reads.read(ExtensionIds.PolicyMappings) { readPolicyMappings(maximumNames) }.orEmpty()

    /**
     * The policy constraints, or null.
     *
     * @since 1.0.0
     */
    public val policyConstraints: PolicyConstraints? =
        reads.read(ExtensionIds.PolicyConstraints) { readPolicyConstraints() }

    /**
     * After how many certificates anyPolicy stops counting, or null.
     *
     * @since 1.0.0
     */
    public val inhibitAnyPolicy: Int? = reads.read(ExtensionIds.InhibitAnyPolicy) { readSkipCount() }

    /**
     * The distribution points of revocation lists, or an empty list.
     *
     * @since 1.0.0
     */
    public val crlDistributionPoints: List<DistributionPoint> =
        reads.read(ExtensionIds.CrlDistributionPoints) { readDistributionPoints(maximumNames) }.orEmpty()

    /**
     * The distribution points of delta revocation lists, or an empty list.
     *
     * @since 1.0.0
     */
    public val freshestCrl: List<DistributionPoint> =
        reads.read(ExtensionIds.FreshestCrl) { readDistributionPoints(maximumNames) }.orEmpty()

    /**
     * The access to information about the issuer, or an empty list.
     *
     * @since 1.0.0
     */
    public val authorityInformationAccess: List<AccessDescription> =
        reads.read(ExtensionIds.AuthorityInformationAccess) { readAccessDescriptions(maximumNames) }.orEmpty()

    /**
     * The access to information about the subject, or an empty list.
     *
     * @since 1.0.0
     */
    public val subjectInformationAccess: List<AccessDescription> =
        reads.read(ExtensionIds.SubjectInformationAccess) { readAccessDescriptions(maximumNames) }.orEmpty()

    /**
     * The TLS features of RFC 7633, such as 5 for OCSP must-staple, or an empty set.
     *
     * @since 1.0.0
     */
    public val tlsFeatures: Set<Int> = reads.read(ExtensionIds.TlsFeature) { readTlsFeatures(maximumNames) }.orEmpty()

    /**
     * Whether the extension OCSP no-check is present.
     *
     * @since 1.0.0
     */
    public val isOcspNoCheck: Boolean = reads.read(ExtensionIds.OcspNoCheck) { readNull() } != null

    /**
     * The identifiers of the critical extensions krypt does not know; a path with one of them is invalid.
     *
     * @since 1.0.0
     */
    public val unknownCritical: List<ObjectIdentifier> =
        unknownOf(all)

    internal constructor(parts: ExtensionParts) : this(parts.all, parts.maximumNames)

    /**
     * Returns the extension [id].
     *
     * @param id the identifier.
     * @return the extension, or null.
     * @since 1.0.0
     */
    public operator fun get(id: ObjectIdentifier): Extension? = all.firstOrNull { extension -> extension.id == id }

    /**
     * Compares the extensions.
     *
     * @param other the other object.
     * @return true if [other] holds the same extensions.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is Extensions && all == other.all

    /**
     * Hashes the extensions.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = all.hashCode()

    /**
     * Shows the extensions.
     *
     * @return the extensions as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Extensions($all)"

    internal companion object {
        val Empty: Extensions = Extensions(ExtensionParts(emptyList(), 1))

        private fun unknownOf(all: List<Extension>): List<ObjectIdentifier> {
            val critical = all.filter { extension -> extension.isCritical }
            return critical.map { extension -> extension.id }.filter { id -> id !in ExtensionReads.KNOWN }
        }
    }
}
