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

package com.davils.krypt.cms.internal

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerElement
import com.davils.krypt.asn1.DerLimits
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readTime
import com.davils.krypt.cms.CertificateReference
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.internal.Algorithms.readDigestAlgorithm
import com.davils.krypt.cms.internal.AttributeCodec.readAttributeSet
import com.davils.krypt.cms.internal.References.readReference
import com.davils.krypt.cms.signed.SignedData
import com.davils.krypt.cms.signed.SignerInfo
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.crl.RevocationList
import com.davils.krypt.x509.crl.RevocationLists
import kotlinx.io.bytestring.ByteString

private const val MAXIMUM_DEPTH: Int = 96
private const val ISSUER_SERIAL_VERSION: Int = 1
private const val KEY_IDENTIFIER_VERSION: Int = 3
private const val UNUSED_VERSION: Int = 2
private const val CONTENT: Int = 0

internal class SignedCodec(crypto: Crypto, private val limits: CmsLimits) {
    private val certificates = Certificates(crypto)
    private val revocationLists = RevocationLists(crypto)

    val derLimits: DerLimits = DerLimits(maximumBytes = limits.maximumBytes, maximumDepth = MAXIMUM_DEPTH)

    fun decode(encoded: ByteString): SignedData? = Der.decodeOrNull(encoded, derLimits) { readSigned(encoded) }

    fun decodeOwn(encoded: ByteString): SignedData = successOf(Der.decode(encoded, derLimits) { readSigned(encoded) })

    private fun DerReader.readSigned(encoded: ByteString): SignedData =
        readContentInfo(ContentTypes.SignedData) { readSignedData(encoded) }

    fun <T> value(encoded: ByteString, block: DerReader.() -> T): T =
        Der.decodeOrNull(encoded, derLimits, block) ?: malformed("an attribute value")

    private fun DerReader.readSignedData(encoded: ByteString): SignedData = readSequence {
        val version = readInt(ISSUER_SERIAL_VERSION..KEY_IDENTIFIER_VERSION)
        if (version == UNUSED_VERSION) malformed("version 1 or 3 of signed data")
        val digests = readElement(Tag.Set)
        setChildren(digests, limits.maximumSigners, isSorted = false).forEach { child ->
            child.parse(Tag.Sequence) { readRemainingElements() }
        }
        val encapsulated = readElement(Tag.Sequence)
        val (contentType, content) = encapsulated.parse(Tag.Sequence) { readEncapsulated() }
        val certificateSet = readOptional(Tag.context(number = 0, isConstructed = true))
        val listSet = readOptional(Tag.context(number = 1, isConstructed = true))
        val signers = readSetElements(
            Tag.Set,
            limits.maximumSigners,
            isSorted = false,
        ).map { element -> signerOf(element, 0) }
        val parts = SignedParts(
            version = version,
            digestAlgorithms = digests.encoded,
            contentType = contentType,
            content = content,
            encapsulated = encapsulated.encoded,
            certificates = certificateSet?.let { found -> certificatesOf(found) }.orEmpty(),
            revocationLists = listSet?.let { found -> revocationListsOf(found) }.orEmpty(),
            signers = signers,
            encoded = encoded,
        )
        SignedData(parts)
    }

    private fun DerReader.readEncapsulated(): Pair<ObjectIdentifier, ByteString?> {
        val contentType = readObjectIdentifier()
        val content = readOptionalExplicit(CONTENT) { readOctetString() }
        val size = content?.size ?: 0
        if (size > limits.maximumContentBytes) limited("a content of at most ${limits.maximumContentBytes} bytes")
        return contentType to content
    }

    private fun certificatesOf(element: DerElement): List<Certificate> =
        setChildren(element, limits.maximumCertificates, isSorted = false).map { child ->
            if (child.tag != Tag.Sequence) malformed("an X.509 certificate")
            certificates.decode(child.encoded).getOrNull() ?: malformed("a valid certificate")
        }

    private fun revocationListsOf(element: DerElement): List<RevocationList> =
        setChildren(element, limits.maximumRevocationLists, isSorted = false).map { child ->
            if (child.tag != Tag.Sequence) malformed("an X.509 revocation list")
            revocationLists.decode(child.encoded).getOrNull() ?: malformed("a valid revocation list")
        }

    fun signerOf(element: DerElement, depth: Int): SignerInfo = element.parse(Tag.Sequence) {
        val version = readInt(ISSUER_SERIAL_VERSION..KEY_IDENTIFIER_VERSION)
        val identifier = readReference()
        val isKeyIdentifier = identifier is CertificateReference.KeyIdentifier
        val expected = listOf(ISSUER_SERIAL_VERSION, KEY_IDENTIFIER_VERSION)[isKeyIdentifier.compareTo(false)]
        if (version != expected) malformed("version $expected of a signer")
        val digest = readDigestAlgorithm()
        val signedSet = takeIf { isNext(SIGNED) }?.readAttributeSet(SIGNED, limits.maximumAttributes, isSorted = true)
        val signed = signedSet?.let { set -> signedOf(set) }
        val algorithmElement = readElement(Tag.Sequence)
        val signature = readOctetString()
        val unsigned = takeIf {
            isNext(
                UNSIGNED,
            )
        }?.readAttributeSet(UNSIGNED, limits.maximumAttributes, isSorted = false)
        val content = element.content
        val unsignedSize = unsigned.mapOr(absent = { 0 }, present = { set -> set.element.encoded.size })
        val parts = SignerParts(
            version = version,
            identifier = identifier,
            digestAlgorithm = digest,
            signed = signed,
            signatureAlgorithm = Algorithms.signatureAlgorithmOf(algorithmElement, digest),
            signature = signature,
            unsigned = unsigned?.attributes.orEmpty(),
            fields = content.substring(startIndex = 0, endIndex = content.size - unsignedSize),
            encoded = element.encoded,
            details = detailsOf(unsigned = unsigned, depth = depth),
        )
        SignerInfo(parts)
    }

    private fun signedOf(set: AttributeSet): SignedAttributes {
        val types = set.attributes.map { attribute -> attribute.type }
        if (types.size != types.toSet().size) malformed("signed attributes of distinct types")
        val contentType = AttributeCodec.single(set, CmsOids.CONTENT_TYPE)
        val digest = AttributeCodec.single(set, CmsOids.MESSAGE_DIGEST) ?: malformed("a message-digest attribute")
        val time = AttributeCodec.single(set, CmsOids.SIGNING_TIME)
        return SignedAttributes(
            set = set,
            messageDigest = value(digest) { readOctetString() },
            contentType = contentType?.let { value -> value(value) { readObjectIdentifier() } },
            signingTime = time?.let { value -> value(value) { readTime() } },
            encoded = set.asSet,
        )
    }

    private fun detailsOf(unsigned: AttributeSet?, depth: Int): SignerDetails {
        val counterAttributes = unsigned?.all(CmsOids.COUNTERSIGNATURE).orEmpty()
        val counters = counterAttributes.flatMap { attribute -> attribute.values }
        if (counters.size > limits.maximumSigners) limited("at most ${limits.maximumSigners} countersignatures")
        val isNested = counters.isNotEmpty() && depth >= limits.maximumNesting
        if (isNested) limited("countersignatures at most ${limits.maximumNesting} deep")
        val tokens = unsigned?.all(CmsOids.TIME_STAMP_TOKEN).orEmpty()
        return SignerDetails(
            countersignatures = counters.map { value -> value(value) { signerOf(readElement(), depth + 1) } },
            timeStampTokens = tokens.flatMap { attribute -> attribute.values },
        )
    }

    private fun DerReader.readRemainingElements() {
        while (!isExhausted) readElement()
    }

    companion object {
        val SIGNED: Tag = Tag.context(number = 0, isConstructed = true)
        val UNSIGNED: Tag = Tag.context(number = 1, isConstructed = true)

        fun <T> DerReader.readContentInfo(type: ObjectIdentifier, block: DerReader.() -> T): T = readSequence {
            if (readObjectIdentifier() != type) malformed("content of type ${type.dotted}")
            readExplicit(CONTENT, block)
        }
    }
}
