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

package com.davils.krypt.authority.profile

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

private const val LEAF_DAYS: Int = 397
private const val SIGNING_DAYS: Int = 1_095
private const val RESPONDER_DAYS: Int = 90
private const val SVID_DAYS: Int = 1
private const val AUTHORITY_DAYS: Int = 1_826

/**
 * What a certificate is for: its key usages, its purposes, the names it may carry and how long it may live.
 *
 * The profiles of the companion cover TLS servers and clients, mutual TLS, code signing, OCSP responders, time
 * stamping, email, SPIFFE X.509-SVIDs and intermediate authorities; a profile of its own is a new instance.
 *
 * @property name the name, shown in requests and audit entries.
 * @param keyUsages the key usages; the extension is critical.
 * @param purposes the extended key usages, or none for no extension.
 * @param nameKinds the kinds of subject alternative names the certificate may carry.
 * @property isNameRequired whether the certificate must carry at least one subject alternative name.
 * @property isCa whether the certificate is an authority.
 * @property pathLength the path length of an authority, or null for none.
 * @property maximumValidity the longest validity.
 * @param rules the rules beyond the key usages and the purposes.
 * @constructor Creates the profile.
 * @throws IllegalArgumentException if [name] is blank, [maximumValidity] is not positive, [pathLength] is negative
 *   or set for a profile that is no authority, or [keyUsages] is empty.
 * @since 1.0.0
 */
public class CertificateProfile(
    public val name: String,
    keyUsages: Set<KeyUsage>,
    purposes: List<ObjectIdentifier> = emptyList(),
    nameKinds: Set<NameKind> = emptySet(),
    public val isNameRequired: Boolean = false,
    public val isCa: Boolean = false,
    public val pathLength: Int? = null,
    public val maximumValidity: Duration = LEAF_DAYS.days,
    rules: Set<ProfileRule> = emptySet(),
) {
    /**
     * The key usages; the extension is critical.
     *
     * @since 1.0.0
     */
    public val keyUsages: Set<KeyUsage> = keyUsages.toSet()

    /**
     * The extended key usages, or none for no extension.
     *
     * @since 1.0.0
     */
    public val purposes: List<ObjectIdentifier> = purposes.toList()

    /**
     * The kinds of subject alternative names the certificate may carry.
     *
     * @since 1.0.0
     */
    public val nameKinds: Set<NameKind> = nameKinds.toSet()

    /**
     * The rules beyond the key usages and the purposes.
     *
     * @since 1.0.0
     */
    public val rules: Set<ProfileRule> = rules.toSet()

    init {
        require(name.isNotBlank()) { "A profile has a name" }
        require(maximumValidity.isPositive()) { "A profile allows a positive validity" }
        require(this.keyUsages.isNotEmpty()) { "A profile has key usages" }
        val isPathValid = pathLength == null || (isCa && pathLength >= 0)
        require(isPathValid) { "Only an authority has a path length, and it is not negative" }
    }

    /**
     * Compares every field.
     *
     * @param other the other object.
     * @return true if [other] is the same profile.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CertificateProfile && values() == other.values()

    /**
     * Hashes every field.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values().hashCode()

    /**
     * Shows the name of the profile.
     *
     * @return the profile as text.
     * @since 1.0.0
     */
    @OptIn(DavilsInternal::class)
    override fun toString(): String = "CertificateProfile(${SafeText.text(name)})"

    private fun values(): List<Any?> =
        listOf(name, keyUsages, purposes, nameKinds, isNameRequired, isCa, pathLength, maximumValidity, rules)

    /**
     * The common profiles.
     *
     * @since 1.0.0
     */
    public companion object {
        private val SIGNATURE: Set<KeyUsage> = setOf(KeyUsage.DigitalSignature)
        private val NETWORK: Set<NameKind> = setOf(NameKind.Dns, NameKind.IpAddress)

        /**
         * A TLS server: DNS names or IP addresses, at least one, for 397 days at most.
         *
         * @since 1.0.0
         */
        public val TlsServer: CertificateProfile = CertificateProfile(
            name = "tls-server",
            keyUsages = SIGNATURE,
            purposes = listOf(KeyPurposes.ServerAuth),
            nameKinds = NETWORK,
            isNameRequired = true,
            rules = setOf(ProfileRule.RsaKeyEncipherment),
        )

        /**
         * A TLS client: any names, none required, for 397 days at most.
         *
         * @since 1.0.0
         */
        public val TlsClient: CertificateProfile = CertificateProfile(
            name = "tls-client",
            keyUsages = SIGNATURE,
            purposes = listOf(KeyPurposes.ClientAuth),
            nameKinds = NameKind.entries.toSet(),
        )

        /**
         * A peer of mutual TLS that serves and connects: DNS names, IP addresses or URIs, at least one.
         *
         * @since 1.0.0
         */
        public val Mtls: CertificateProfile = CertificateProfile(
            name = "mtls",
            keyUsages = SIGNATURE,
            purposes = listOf(KeyPurposes.ServerAuth, KeyPurposes.ClientAuth),
            nameKinds = NETWORK + NameKind.Uri,
            isNameRequired = true,
            rules = setOf(ProfileRule.RsaKeyEncipherment),
        )

        /**
         * Code signing, for three years at most.
         *
         * @since 1.0.0
         */
        public val CodeSigning: CertificateProfile = CertificateProfile(
            name = "code-signing",
            keyUsages = SIGNATURE,
            purposes = listOf(KeyPurposes.CodeSigning),
            maximumValidity = SIGNING_DAYS.days,
        )

        /**
         * A delegated OCSP responder, with ocsp-nocheck, for 90 days at most.
         *
         * @since 1.0.0
         */
        public val OcspSigning: CertificateProfile = CertificateProfile(
            name = "ocsp-signing",
            keyUsages = SIGNATURE,
            purposes = listOf(KeyPurposes.OcspSigning),
            maximumValidity = RESPONDER_DAYS.days,
            rules = setOf(ProfileRule.OcspNoCheck),
        )

        /**
         * A time-stamping authority (RFC 3161), with its purpose critical, for three years at most.
         *
         * @since 1.0.0
         */
        public val TimeStamping: CertificateProfile = CertificateProfile(
            name = "time-stamping",
            keyUsages = setOf(KeyUsage.DigitalSignature, KeyUsage.ContentCommitment),
            purposes = listOf(KeyPurposes.TimeStamping),
            maximumValidity = SIGNING_DAYS.days,
            rules = setOf(ProfileRule.CriticalPurposes),
        )

        /**
         * Email protection: email addresses, at least one.
         *
         * @since 1.0.0
         */
        public val Email: CertificateProfile = CertificateProfile(
            name = "email",
            keyUsages = SIGNATURE,
            purposes = listOf(KeyPurposes.EmailProtection),
            nameKinds = setOf(NameKind.Email),
            isNameRequired = true,
            rules = setOf(ProfileRule.RsaKeyEncipherment),
        )

        /**
         * A SPIFFE X.509-SVID: exactly one URI, the SPIFFE id, for a day at most.
         *
         * @since 1.0.0
         */
        public val SpiffeSvid: CertificateProfile = CertificateProfile(
            name = "spiffe-svid",
            keyUsages = SIGNATURE,
            purposes = listOf(KeyPurposes.ServerAuth, KeyPurposes.ClientAuth),
            nameKinds = setOf(NameKind.Uri),
            isNameRequired = true,
            maximumValidity = SVID_DAYS.days,
            rules = setOf(ProfileRule.SingleUri),
        )

        /**
         * An intermediate authority, for five years at most.
         *
         * @param pathLength how many authorities may follow it, or null for no limit.
         * @return the profile.
         * @throws IllegalArgumentException if [pathLength] is negative.
         * @since 1.0.0
         */
        public fun intermediate(pathLength: Int? = null): CertificateProfile = CertificateProfile(
            name = "intermediate",
            keyUsages = setOf(KeyUsage.KeyCertSign, KeyUsage.CrlSign, KeyUsage.DigitalSignature),
            isCa = true,
            pathLength = pathLength,
            maximumValidity = AUTHORITY_DAYS.days,
        )
    }
}
