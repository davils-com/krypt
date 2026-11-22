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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.cms.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.cms.Attribute
import com.davils.krypt.cms.CertificateReference
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.internal.Algorithms.writeDigestAlgorithm
import com.davils.krypt.cms.internal.Algorithms.writeShake256
import com.davils.krypt.cms.internal.AttributeCodec.writeAttributes
import com.davils.krypt.cms.internal.References.writeReference
import com.davils.krypt.cms.signed.SignedData
import com.davils.krypt.cms.signed.SignedDataBuilder
import com.davils.krypt.cms.signed.SignerInfo
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.x509.AlgorithmIdentifiers.writeSignatureAlgorithm
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

private const val ISSUER_SERIAL_VERSION: Long = 1
private const val KEY_IDENTIFIER_VERSION: Long = 3
private const val DIRECTORY_NAME: Int = 4

internal class SignedWriter(private val crypto: Crypto, private val limits: CmsLimits) {
    suspend fun sign(content: ByteString, builder: SignedDataBuilder): ByteString {
        require(
            content.size <= limits.maximumContentBytes,
        ) { "The content exceeds ${limits.maximumContentBytes} bytes" }
        require(
            builder.signers.size in 1..limits.maximumSigners,
        ) { "Signed data has 1 to ${limits.maximumSigners} signers" }
        val signers = builder.signers.map { spec ->
            signerInfo(spec = spec, data = content, contentType = builder.contentType)
        }
        val digests = builder.signers.map { spec -> Der.encode { writeDigest(digestOf(spec.signer.algorithm)) } }
        val included = builder.signers.filter { spec -> spec.options.isCertificateIncluded }
        val certificates = included.map { spec -> spec.certificate } + builder.certificates
        val isVersion3 = builder.contentType != ContentTypes.Data ||
            builder.signers.any { spec -> spec.options.isKeyIdentifierUsed }
        val version = listOf(ISSUER_SERIAL_VERSION, KEY_IDENTIFIER_VERSION)[isVersion3.compareTo(false)]
        val encapsulated = Der.encode {
            sequence {
                objectIdentifier(builder.contentType)
                if (!builder.isDetached) explicit(0) { octetString(content) }
            }
        }
        return assemble(
            version = version,
            digestAlgorithms = Der.encode { sortedSet(Tag.Set, digests.distinct()) },
            encapsulated = encapsulated,
            certificates = certificates.map { certificate -> certificate.encoded }.distinct(),
            revocationLists = builder.revocationLists.map { list -> list.encoded }.distinct(),
            signers = signers,
        )
    }

    suspend fun countersign(data: SignedData, target: SignerInfo, spec: SignerSpec): ByteString {
        val counter = signerInfo(spec = spec, data = target.signature, contentType = null)
        val extra = listOf(spec.certificate).filter { spec.options.isCertificateIncluded }
        return withUnsigned(
            data = data,
            target = target,
            attribute = Attribute(CmsOids.COUNTERSIGNATURE, listOf(counter)),
            certificates = extra,
        )
    }

    fun withUnsigned(
        data: SignedData,
        target: SignerInfo,
        attribute: Attribute,
        certificates: List<Certificate> = emptyList(),
    ): ByteString {
        val index = data.signers.indexOf(target)
        require(index >= 0) { "The signer is not one of the signed data" }
        val existing = target.unsignedAttributes
        val merged = existing.firstOrNull { found -> found.type == attribute.type }?.let { found ->
            Attribute(found.type, found.values + attribute.values)
        }
        val others = existing.filter { found -> found.type != attribute.type }
        val unsigned = others + (merged ?: attribute)
        require(
            unsigned.size <= limits.maximumAttributes,
        ) { attributesLimit() }
        val attributes = Der.encode { writeAttributes(SignedCodec.UNSIGNED, unsigned) }
        val updated = Der.encode { element(Tag.Sequence, concat(listOf(target.parts.fields, attributes))) }
        val signers = data.signers.map { signer -> signer.encoded }.toMutableList()
        signers[index] = updated
        val parts = data.parts
        return assemble(
            version = parts.version.toLong(),
            digestAlgorithms = parts.digestAlgorithms,
            encapsulated = parts.encapsulated,
            certificates = (parts.certificates + certificates).map { certificate -> certificate.encoded }.distinct(),
            revocationLists = parts.revocationLists.map { list -> list.encoded },
            signers = signers,
        )
    }

    private suspend fun signerInfo(spec: SignerSpec, data: ByteString, contentType: ObjectIdentifier?): ByteString {
        val signer = spec.signer
        val options = spec.options
        val algorithm = signer.algorithm
        val digest = digestOf(algorithm)
        require(spec.certificate.publicKey == signer.publicKey) { "The certificate is not the one of the signer" }
        val isPermitted = crypto.environment.policy.permits(algorithm, AlgorithmUse.Protect)
        if (!isPermitted) throw PolicyViolationException("${algorithm.algorithmName} (${AlgorithmUse.Protect})")
        require(digest != null || !options.isSignedAttributesUsed) {
            "Ed448 signs without signed attributes, since krypt has no SHAKE256"
        }
        val isTyped = contentType != null && contentType != ContentTypes.Data
        require(options.isSignedAttributesUsed || !isTyped) {
            "A content type other than id-data is signed as a signed attribute (RFC 5652 section 5.3)"
        }
        val reference = References.of(spec.certificate, options.isKeyIdentifierUsed)
        val signed = digest?.takeIf { options.isSignedAttributesUsed }?.let { found ->
            signedAttributes(spec = spec, data = data, digest = found, contentType = contentType)
        }
        val input = signed.mapOr(absent = { data }, present = { attributes -> AttributeCodec.encodeSet(attributes) })
        val signature = signer.sign(input)
        require(options.unsignedAttributes.size <= limits.maximumAttributes) {
            attributesLimit()
        }
        return Der.encode {
            sequence {
                integer(versionOf(reference))
                writeReference(reference)
                writeDigest(digest)
                signed?.let { attributes -> writeAttributes(SignedCodec.SIGNED, attributes) }
                writeSignatureAlgorithm(algorithm)
                octetString(signature)
                if (options.unsignedAttributes.isNotEmpty()) {
                    writeAttributes(SignedCodec.UNSIGNED, options.unsignedAttributes)
                }
            }
        }
    }

    private suspend fun signedAttributes(
        spec: SignerSpec,
        data: ByteString,
        digest: DigestAlgorithm,
        contentType: ObjectIdentifier?,
    ): List<Attribute> {
        val options = spec.options
        val hash = crypto.digests.digest(data = data, algorithm = digest)
        val time = options.signingTime ?: crypto.environment.clock.now()
        val builtIn = listOfNotNull(
            contentType?.let { type -> attribute(CmsOids.CONTENT_TYPE, Der.encode { objectIdentifier(type) }) },
            attribute(CmsOids.MESSAGE_DIGEST, Der.encode { octetString(hash) }),
            attribute(CmsOids.SIGNING_TIME, Der.encode { time(time) }).takeIf { options.isSigningTimeIncluded },
            signingCertificate(spec.certificate).takeIf { options.isSigningCertificateIncluded },
        )
        val all = builtIn + options.signedAttributes
        val types = all.map { attribute -> attribute.type }
        require(types.size == types.toSet().size) { "Signed attributes have distinct types" }
        require(all.size <= limits.maximumAttributes) { attributesLimit() }
        return all
    }

    private suspend fun signingCertificate(certificate: Certificate): Attribute {
        val hash = crypto.digests.digest(data = certificate.encoded, algorithm = DigestAlgorithm.Sha256)
        val value = Der.encode {
            sequence {
                sequence {
                    sequence {
                        octetString(hash)
                        sequence {
                            sequence { explicit(DIRECTORY_NAME) { raw(certificate.issuer.encoded) } }
                            integer(certificate.serialNumber)
                        }
                    }
                }
            }
        }
        return attribute(CmsOids.SIGNING_CERTIFICATE_V2, value)
    }

    private fun attributesLimit(): String = "A signer has at most ${limits.maximumAttributes} attributes"

    private fun attribute(type: ObjectIdentifier, value: ByteString): Attribute = Attribute(type, listOf(value))

    private fun versionOf(reference: CertificateReference): Long = when (reference) {
        is CertificateReference.KeyIdentifier -> KEY_IDENTIFIER_VERSION
        is CertificateReference.IssuerSerial -> ISSUER_SERIAL_VERSION
    }

    private fun DerWriter.writeDigest(digest: DigestAlgorithm?) {
        digest?.let { found -> writeDigestAlgorithm(found) } ?: writeShake256()
    }

    private fun assemble(
        version: Long,
        digestAlgorithms: ByteString,
        encapsulated: ByteString,
        certificates: List<ByteString>,
        revocationLists: List<ByteString>,
        signers: List<ByteString>,
    ): ByteString = Der.encode {
        sequence {
            objectIdentifier(ContentTypes.SignedData)
            explicit(0) {
                sequence {
                    integer(version)
                    raw(digestAlgorithms)
                    raw(encapsulated)
                    if (certificates.isNotEmpty()) {
                        sortedSet(
                            Tag.context(number = 0, isConstructed = true),
                            certificates,
                        )
                    }
                    if (revocationLists.isNotEmpty()) {
                        sortedSet(Tag.context(number = 1, isConstructed = true), revocationLists)
                    }
                    sortedSet(Tag.Set, signers)
                }
            }
        }
    }

    companion object {
        fun digestOf(algorithm: SignatureAlgorithm): DigestAlgorithm? =
            algorithm.digest ?: DigestAlgorithm.Sha512.takeUnless { algorithm == SignatureAlgorithm.Ed448 }
    }
}
