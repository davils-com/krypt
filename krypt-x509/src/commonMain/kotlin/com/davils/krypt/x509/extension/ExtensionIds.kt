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

/**
 * The object identifiers of the extensions krypt reads and writes.
 *
 * @since 1.0.0
 */
public object ExtensionIds {
    /**
     * The subject key identifier.
     *
     * @since 1.0.0
     */
    public val SubjectKeyIdentifier: ObjectIdentifier = ObjectIdentifier.of("2.5.29.14")

    /**
     * The key usage.
     *
     * @since 1.0.0
     */
    public val KeyUsage: ObjectIdentifier = ObjectIdentifier.of("2.5.29.15")

    /**
     * The subject alternative name.
     *
     * @since 1.0.0
     */
    public val SubjectAlternativeName: ObjectIdentifier = ObjectIdentifier.of("2.5.29.17")

    /**
     * The issuer alternative name.
     *
     * @since 1.0.0
     */
    public val IssuerAlternativeName: ObjectIdentifier = ObjectIdentifier.of("2.5.29.18")

    /**
     * The basic constraints.
     *
     * @since 1.0.0
     */
    public val BasicConstraints: ObjectIdentifier = ObjectIdentifier.of("2.5.29.19")

    /**
     * The number of a revocation list.
     *
     * @since 1.0.0
     */
    public val CrlNumber: ObjectIdentifier = ObjectIdentifier.of("2.5.29.20")

    /**
     * The reason of a revocation list entry.
     *
     * @since 1.0.0
     */
    public val ReasonCode: ObjectIdentifier = ObjectIdentifier.of("2.5.29.21")

    /**
     * The invalidity date of a revocation list entry.
     *
     * @since 1.0.0
     */
    public val InvalidityDate: ObjectIdentifier = ObjectIdentifier.of("2.5.29.24")

    /**
     * The indicator of a delta revocation list.
     *
     * @since 1.0.0
     */
    public val DeltaCrlIndicator: ObjectIdentifier = ObjectIdentifier.of("2.5.29.27")

    /**
     * The issuing distribution point of a revocation list.
     *
     * @since 1.0.0
     */
    public val IssuingDistributionPoint: ObjectIdentifier = ObjectIdentifier.of("2.5.29.28")

    /**
     * The certificate issuer of an entry of an indirect revocation list.
     *
     * @since 1.0.0
     */
    public val CertificateIssuer: ObjectIdentifier = ObjectIdentifier.of("2.5.29.29")

    /**
     * The name constraints.
     *
     * @since 1.0.0
     */
    public val NameConstraints: ObjectIdentifier = ObjectIdentifier.of("2.5.29.30")

    /**
     * The distribution points of revocation lists.
     *
     * @since 1.0.0
     */
    public val CrlDistributionPoints: ObjectIdentifier = ObjectIdentifier.of("2.5.29.31")

    /**
     * The certificate policies.
     *
     * @since 1.0.0
     */
    public val CertificatePolicies: ObjectIdentifier = ObjectIdentifier.of("2.5.29.32")

    /**
     * The policy mappings.
     *
     * @since 1.0.0
     */
    public val PolicyMappings: ObjectIdentifier = ObjectIdentifier.of("2.5.29.33")

    /**
     * The authority key identifier.
     *
     * @since 1.0.0
     */
    public val AuthorityKeyIdentifier: ObjectIdentifier = ObjectIdentifier.of("2.5.29.35")

    /**
     * The policy constraints.
     *
     * @since 1.0.0
     */
    public val PolicyConstraints: ObjectIdentifier = ObjectIdentifier.of("2.5.29.36")

    /**
     * The extended key usage.
     *
     * @since 1.0.0
     */
    public val ExtendedKeyUsage: ObjectIdentifier = ObjectIdentifier.of("2.5.29.37")

    /**
     * The distribution points of delta revocation lists.
     *
     * @since 1.0.0
     */
    public val FreshestCrl: ObjectIdentifier = ObjectIdentifier.of("2.5.29.46")

    /**
     * The inhibition of anyPolicy.
     *
     * @since 1.0.0
     */
    public val InhibitAnyPolicy: ObjectIdentifier = ObjectIdentifier.of("2.5.29.54")

    /**
     * The access to information about the issuer, such as its OCSP responder.
     *
     * @since 1.0.0
     */
    public val AuthorityInformationAccess: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.1.1")

    /**
     * The access to information about the subject.
     *
     * @since 1.0.0
     */
    public val SubjectInformationAccess: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.1.11")

    /**
     * The TLS features of RFC 7633, such as OCSP must-staple.
     *
     * @since 1.0.0
     */
    public val TlsFeature: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.1.24")

    /**
     * The marker of an OCSP signer whose own status is not checked.
     *
     * @since 1.0.0
     */
    public val OcspNoCheck: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.48.1.5")

    /**
     * The signed certificate timestamps of Certificate Transparency.
     *
     * @since 1.0.0
     */
    public val SignedCertificateTimestamps: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.11129.2.4.2")

    /**
     * The poison of a precertificate of Certificate Transparency.
     *
     * @since 1.0.0
     */
    public val PrecertificatePoison: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.11129.2.4.3")
}
