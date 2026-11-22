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

package com.davils.krypt.x509.internal

import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.DerElement
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readListOf
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.extension.AccessDescription
import com.davils.krypt.x509.extension.AuthorityKeyIdentifier
import com.davils.krypt.x509.extension.BasicConstraints
import com.davils.krypt.x509.extension.DistributionPoint
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.extension.PolicyConstraints
import com.davils.krypt.x509.extension.PolicyMapping
import com.davils.krypt.x509.internal.NameCodec.readGeneralName
import com.davils.krypt.x509.name.GeneralName
import kotlinx.io.bytestring.ByteString

private const val KEY_IDENTIFIER: Int = 0
private const val AUTHORITY_ISSUER: Int = 1
private const val AUTHORITY_SERIAL: Int = 2
private const val PERMITTED: Int = 0
private const val EXCLUDED: Int = 1
private const val REQUIRE_EXPLICIT: Int = 0
private const val INHIBIT_MAPPING: Int = 1
private const val POINT_NAME: Int = 0
private const val POINT_REASONS: Int = 1
private const val POINT_ISSUER: Int = 2
private const val FULL_NAME: Int = 0
private const val MAXIMUM_FEATURE: Int = 65_535
private const val BYTE_BITS: Int = 8

internal object ExtensionReads {
    val KNOWN: Set<ObjectIdentifier> = setOf(
        ExtensionIds.SubjectKeyIdentifier,
        ExtensionIds.KeyUsage,
        ExtensionIds.SubjectAlternativeName,
        ExtensionIds.IssuerAlternativeName,
        ExtensionIds.BasicConstraints,
        ExtensionIds.NameConstraints,
        ExtensionIds.CrlDistributionPoints,
        ExtensionIds.CertificatePolicies,
        ExtensionIds.PolicyMappings,
        ExtensionIds.AuthorityKeyIdentifier,
        ExtensionIds.PolicyConstraints,
        ExtensionIds.ExtendedKeyUsage,
        ExtensionIds.FreshestCrl,
        ExtensionIds.InhibitAnyPolicy,
        ExtensionIds.AuthorityInformationAccess,
        ExtensionIds.SubjectInformationAccess,
        ExtensionIds.TlsFeature,
        ExtensionIds.OcspNoCheck,
    )

    fun DerReader.readBasicConstraints(): BasicConstraints = readSequence {
        val isCa = Tag.Boolean.takeIf { tag -> isNext(tag) }?.let { readBoolean() } == true
        val pathLength = Tag.Integer.takeIf { tag -> isNext(tag) }?.let { readInt(0..Int.MAX_VALUE) }
        if (pathLength != null && !isCa) refuse(DerFailure.InvalidValue, "a path length of an authority only")
        BasicConstraints(isCa = isCa, pathLength = pathLength)
    }

    fun DerReader.readKeyUsage(): Set<KeyUsage> {
        val bits = readBitString()
        val usages = KeyUsage.entries.filter { usage -> usage.bit < bits.size && bits[usage.bit] }.toSet()
        if (usages.isEmpty()) refuse(DerFailure.InvalidValue, "at least one key usage")
        return usages
    }

    fun DerReader.readKeyPurposes(maximum: Int): List<ObjectIdentifier> {
        val purposes = readListOf(maximum) { readObjectIdentifier() }
        if (purposes.isEmpty()) refuse(DerFailure.InvalidValue, "at least one key purpose")
        return purposes
    }

    fun DerReader.readAuthorityKeyIdentifier(maximum: Int): AuthorityKeyIdentifier = readSequence {
        val keyIdentifier = readOptional(Tag.context(number = KEY_IDENTIFIER, isConstructed = false))?.content
        val issuer = readOptional(Tag.context(number = AUTHORITY_ISSUER, isConstructed = true))?.let { element ->
            namesOf(element.reader(), maximum)
        }
        val serial = readOptional(Tag.context(number = AUTHORITY_SERIAL, isConstructed = false))?.let { element ->
            DerInteger.decodeOrNull(element.content) ?: refuse(DerFailure.InvalidValue, "a serial number")
        }
        AuthorityKeyIdentifier(keyIdentifier = keyIdentifier, issuer = issuer.orEmpty(), serialNumber = serial)
    }

    fun DerReader.readNameConstraints(maximum: Int): NameConstraints = readSequence {
        val permitted = readOptional(Tag.context(number = PERMITTED, isConstructed = true))?.let { element ->
            subtreesOf(element.reader(), maximum)
        }
        val excluded = readOptional(Tag.context(number = EXCLUDED, isConstructed = true))?.let { element ->
            subtreesOf(element.reader(), maximum)
        }
        if (permitted == null && excluded == null) refuse(DerFailure.InvalidValue, "at least one subtree")
        NameConstraints(permitted = permitted.orEmpty(), excluded = excluded.orEmpty())
    }

    fun DerReader.readPolicies(maximum: Int): List<ObjectIdentifier> {
        val policies = readListOf(maximum) {
            readSequence {
                val policy = readObjectIdentifier()
                if (isNext(Tag.Sequence)) readElement()
                policy
            }
        }
        val isDistinct = policies.toSet().size == policies.size
        if (policies.isEmpty() || !isDistinct) refuse(DerFailure.InvalidValue, "distinct policies")
        return policies
    }

    fun DerReader.readPolicyMappings(maximum: Int): List<PolicyMapping> {
        val mappings = readListOf(maximum) {
            readSequence {
                PolicyMapping(
                    issuerPolicy = readObjectIdentifier(),
                    subjectPolicy = readObjectIdentifier(),
                )
            }
        }
        if (mappings.isEmpty()) refuse(DerFailure.InvalidValue, "at least one policy mapping")
        return mappings
    }

    fun DerReader.readPolicyConstraints(): PolicyConstraints = readSequence {
        val require = readOptional(
            Tag.context(number = REQUIRE_EXPLICIT, isConstructed = false),
        )?.let { skipOf(it.content) }
        val inhibit = readOptional(
            Tag.context(number = INHIBIT_MAPPING, isConstructed = false),
        )?.let { skipOf(it.content) }
        if (require == null && inhibit == null) refuse(DerFailure.InvalidValue, "a policy constraint")
        PolicyConstraints(requireExplicitPolicy = require, inhibitPolicyMapping = inhibit)
    }

    fun DerReader.readSkipCount(): Int = readInt(0..Int.MAX_VALUE)

    fun DerReader.readDistributionPoints(maximum: Int): List<DistributionPoint> {
        val points = readListOf(maximum) { readSequence { readDistributionPoint(maximum) } }
        if (points.isEmpty()) refuse(DerFailure.InvalidValue, "at least one distribution point")
        return points
    }

    fun DerReader.readAccessDescriptions(maximum: Int): List<AccessDescription> {
        val descriptions = readListOf(maximum) {
            readSequence { AccessDescription(method = readObjectIdentifier(), location = readGeneralName(maximum)) }
        }
        if (descriptions.isEmpty()) refuse(DerFailure.InvalidValue, "at least one access description")
        return descriptions
    }

    fun DerReader.readTlsFeatures(maximum: Int): Set<Int> {
        val features = readListOf(maximum) { readInt(0..MAXIMUM_FEATURE) }
        return features.toSet()
    }

    fun reasonsOf(bits: BitString): Set<RevocationReason> {
        val reasons = RevocationReason.entries.filter { reason -> isSet(bits, reason.bit) }
        return reasons.toSet()
    }

    private fun isSet(bits: BitString, bit: Int?): Boolean = bit != null && bit < bits.size && bits[bit]

    private fun DerReader.readDistributionPoint(maximum: Int): DistributionPoint {
        val name = readOptional(
            Tag.context(number = POINT_NAME, isConstructed = true),
        )?.let { element -> pointNamesOf(element, maximum) }
        val reasons = readOptional(Tag.context(number = POINT_REASONS, isConstructed = false))?.let { element ->
            reasonsOf(bitStringOf(element.content))
        }
        val issuer = readOptional(Tag.context(number = POINT_ISSUER, isConstructed = true))?.let { element ->
            namesOf(element.reader(), maximum)
        }
        return DistributionPoint(names = name.orEmpty(), reasons = reasons, crlIssuer = issuer.orEmpty())
    }

    private fun pointNamesOf(element: DerElement, maximum: Int): List<GeneralName>? {
        val inner = element.reader()
        val full = inner.readOptional(Tag.context(number = FULL_NAME, isConstructed = true))
        val names = full?.let { found -> namesOf(found.reader(), maximum) }
        if (names == null) inner.readElement()
        return names
    }

    fun namesOf(reader: DerReader, maximum: Int): List<GeneralName> {
        val names = mutableListOf<GeneralName>()
        while (!reader.isExhausted) {
            if (names.size >= maximum) reader.refuse(DerFailure.LimitExceeded, "at most $maximum names")
            names += reader.readGeneralName(maximum)
        }
        if (names.isEmpty()) reader.refuse(DerFailure.InvalidValue, "at least one name")
        return names
    }

    private fun subtreesOf(reader: DerReader, maximum: Int): List<GeneralName> {
        val names = mutableListOf<GeneralName>()
        while (!reader.isExhausted) {
            if (names.size >= maximum) reader.refuse(DerFailure.LimitExceeded, "at most $maximum subtrees")
            names += reader.readSequence {
                val base = readGeneralName(maximum)
                if (!isExhausted) refuse(DerFailure.InvalidValue, "a subtree without minimum and maximum")
                base
            }
        }
        if (names.isEmpty()) reader.refuse(DerFailure.InvalidValue, "at least one subtree")
        return names
    }

    private fun DerReader.skipOf(content: ByteString): Int {
        val value = DerInteger.decodeOrNull(content)?.toLongOrNull()
        return value?.takeIf { found -> found in 0..Int.MAX_VALUE }?.toInt() ?: refuse(
            DerFailure.InvalidValue,
            "a skip count",
        )
    }

    fun DerReader.bitStringOf(content: ByteString): BitString {
        val first = content.toByteArray().firstOrNull()
        val unused = first?.toInt() ?: -1
        val isValid = unused in 0..<BYTE_BITS && (content.size > 1 || unused == 0)
        if (!isValid) refuse(DerFailure.InvalidValue, "a bit string")
        return BitString(content.substring(1), unused)
    }
}
