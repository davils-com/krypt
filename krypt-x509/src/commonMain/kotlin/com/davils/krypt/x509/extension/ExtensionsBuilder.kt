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

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.x509.internal.ExtensionWrites
import com.davils.krypt.x509.internal.NameCodec.writeGeneralName
import com.davils.krypt.x509.name.GeneralName
import kotlinx.io.bytestring.ByteString

private const val STATUS_REQUEST: Int = 5

/**
 * Builds the extensions of a certificate, a request or a revocation list, each at most once and in the order added.
 *
 * The defaults of `critical` follow RFC 5280: basic constraints, key usage, name constraints and the policy
 * constraints are critical, the other extensions are not.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class ExtensionsBuilder internal constructor() {
    internal val extensions: MutableList<Extension> = mutableListOf()

    /**
     * Adds [extension] as it is.
     *
     * @param extension the extension.
     * @throws IllegalArgumentException if an extension with its identifier was added already.
     * @since 1.0.0
     */
    public fun add(extension: Extension) {
        require(
            extensions.none { found -> found.id == extension.id },
        ) { "The extension ${extension.id.dotted} is there" }
        extensions += extension
    }

    /**
     * Adds the basic constraints.
     *
     * @param isCa whether the subject is a certificate authority.
     * @param pathLength the most intermediate authorities below it, or null.
     * @param critical whether the extension is critical; true by default.
     * @since 1.0.0
     */
    public fun basicConstraints(isCa: Boolean, pathLength: Int? = null, critical: Boolean = true) {
        val constraints = BasicConstraints(isCa = isCa, pathLength = pathLength)
        add(
            ExtensionIds.BasicConstraints,
            critical,
            Der.encode {
                sequence {
                    if (constraints.isCa) boolean(true)
                    constraints.pathLength?.let { length -> integer(length.toLong()) }
                }
            },
        )
    }

    /**
     * Adds the key usage.
     *
     * @param usages the usages; at least one.
     * @param critical whether the extension is critical; true by default.
     * @throws IllegalArgumentException if [usages] is empty.
     * @since 1.0.0
     */
    public fun keyUsage(usages: Set<KeyUsage>, critical: Boolean = true) {
        require(usages.isNotEmpty()) { "A key usage names at least one usage" }
        val bits = BitString.ofNamedBits(usages.map { usage -> usage.bit }.toSet())
        add(ExtensionIds.KeyUsage, critical, Der.encode { bitString(bits) })
    }

    /**
     * Adds the extended key usage.
     *
     * @param purposes the key purposes, such as [KeyPurposes.ServerAuth]; at least one.
     * @param critical whether the extension is critical; false by default.
     * @throws IllegalArgumentException if [purposes] is empty.
     * @since 1.0.0
     */
    public fun extendedKeyUsage(purposes: List<ObjectIdentifier>, critical: Boolean = false) {
        require(purposes.isNotEmpty()) { "An extended key usage names at least one purpose" }
        add(ExtensionIds.ExtendedKeyUsage, critical, ExtensionWrites.objectIdentifiers(purposes))
    }

    /**
     * Adds the subject alternative names.
     *
     * @param names the names; at least one.
     * @param critical whether the extension is critical; false by default, true for a subject with an empty name.
     * @throws IllegalArgumentException if [names] is empty.
     * @since 1.0.0
     */
    public fun subjectAlternativeNames(names: List<GeneralName>, critical: Boolean = false) {
        require(names.isNotEmpty()) { "Alternative names name at least one name" }
        add(ExtensionIds.SubjectAlternativeName, critical, ExtensionWrites.names(names))
    }

    /**
     * Adds the subject key identifier.
     *
     * @param identifier the identifier.
     * @since 1.0.0
     */
    public fun subjectKeyIdentifier(identifier: ByteString) {
        add(ExtensionIds.SubjectKeyIdentifier, false, Der.encode { octetString(identifier) })
    }

    /**
     * Adds the authority key identifier with the key identifier of the issuer.
     *
     * @param identifier the key identifier of the issuer.
     * @since 1.0.0
     */
    public fun authorityKeyIdentifier(identifier: ByteString) {
        add(
            ExtensionIds.AuthorityKeyIdentifier,
            false,
            Der.encode { sequence { octetString(identifier, Tag.context(number = 0, isConstructed = false)) } },
        )
    }

    /**
     * Adds the name constraints.
     *
     * @param constraints the constraints.
     * @param critical whether the extension is critical; true by default.
     * @since 1.0.0
     */
    public fun nameConstraints(constraints: NameConstraints, critical: Boolean = true) {
        val value = Der.encode {
            sequence {
                listOf(constraints.permitted, constraints.excluded).forEachIndexed { index, subtrees ->
                    if (subtrees.isNotEmpty()) {
                        constructed(Tag.context(number = index, isConstructed = true)) {
                            subtrees.forEach { name -> sequence { writeGeneralName(name) } }
                        }
                    }
                }
            }
        }
        add(ExtensionIds.NameConstraints, critical, value)
    }

    /**
     * Adds the certificate policies without qualifiers.
     *
     * @param policies the policies; at least one, each once.
     * @param critical whether the extension is critical; false by default.
     * @throws IllegalArgumentException if [policies] is empty or holds a policy twice.
     * @since 1.0.0
     */
    public fun certificatePolicies(policies: List<ObjectIdentifier>, critical: Boolean = false) {
        require(
            policies.isNotEmpty() && policies.toSet().size == policies.size,
        ) { "Policies are distinct and at least one" }
        val value = Der.encode { sequence { policies.forEach { policy -> sequence { objectIdentifier(policy) } } } }
        add(ExtensionIds.CertificatePolicies, critical, value)
    }

    /**
     * Adds the policy constraints.
     *
     * @param constraints the constraints.
     * @param critical whether the extension is critical; true by default.
     * @since 1.0.0
     */
    public fun policyConstraints(constraints: PolicyConstraints, critical: Boolean = true) {
        val value = Der.encode {
            sequence {
                constraints.requireExplicitPolicy?.let { skip ->
                    integer(
                        skip.toLong(),
                        Tag.context(number = 0, isConstructed = false),
                    )
                }
                constraints.inhibitPolicyMapping?.let { skip ->
                    integer(
                        skip.toLong(),
                        Tag.context(number = 1, isConstructed = false),
                    )
                }
            }
        }
        add(ExtensionIds.PolicyConstraints, critical, value)
    }

    /**
     * Adds the distribution points of revocation lists.
     *
     * @param points the points; at least one.
     * @throws IllegalArgumentException if [points] is empty.
     * @since 1.0.0
     */
    public fun crlDistributionPoints(points: List<DistributionPoint>) {
        require(points.isNotEmpty()) { "At least one distribution point" }
        add(ExtensionIds.CrlDistributionPoints, false, ExtensionWrites.distributionPoints(points))
    }

    /**
     * Adds the access to information about the issuer, such as its OCSP responder and its certificate.
     *
     * @param descriptions the descriptions; at least one.
     * @throws IllegalArgumentException if [descriptions] is empty.
     * @since 1.0.0
     */
    public fun authorityInformationAccess(descriptions: List<AccessDescription>) {
        require(descriptions.isNotEmpty()) { "At least one access description" }
        add(ExtensionIds.AuthorityInformationAccess, false, ExtensionWrites.accessDescriptions(descriptions))
    }

    /**
     * Adds OCSP must-staple, the TLS feature status_request of RFC 7633.
     *
     * @since 1.0.0
     */
    public fun mustStaple() {
        add(ExtensionIds.TlsFeature, false, Der.encode { sequence { integer(STATUS_REQUEST.toLong()) } })
    }

    /**
     * Marks an OCSP signer whose own status is not checked.
     *
     * @since 1.0.0
     */
    public fun ocspNoCheck() {
        add(ExtensionIds.OcspNoCheck, false, Der.encode { nullValue() })
    }

    private fun add(id: ObjectIdentifier, critical: Boolean, value: ByteString) {
        add(Extension(id = id, isCritical = critical, value = value))
    }
}
