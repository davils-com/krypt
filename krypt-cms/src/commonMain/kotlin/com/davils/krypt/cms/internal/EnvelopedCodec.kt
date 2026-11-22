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

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerLimits
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readInt
import com.davils.krypt.cms.Attribute
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.enveloped.EncryptedData
import com.davils.krypt.cms.enveloped.EnvelopedData
import com.davils.krypt.cms.internal.Algorithms.readContentAlgorithm
import com.davils.krypt.cms.internal.Algorithms.writeContentAlgorithm
import com.davils.krypt.cms.internal.AttributeCodec.readAttributeSet
import com.davils.krypt.cms.internal.AttributeCodec.writeAttributes
import kotlinx.io.bytestring.ByteString

private const val MAXIMUM_DEPTH: Int = 64
private const val MAXIMUM_VERSION: Int = 4
private const val ENCRYPTED_MAXIMUM_VERSION: Int = 2
private const val BLOCK: Int = 16

private val FIRST: Tag = Tag.context(number = 1, isConstructed = true)
private val SECOND: Tag = Tag.context(number = 2, isConstructed = true)
private val CONTENT: Tag = Tag.context(number = 0, isConstructed = false)

internal class EnvelopedCodec(private val limits: CmsLimits) {
    private val derLimits = DerLimits(maximumBytes = limits.maximumBytes, maximumDepth = MAXIMUM_DEPTH)

    fun decode(encoded: ByteString): EnvelopedData? = Der.decodeOrNull(encoded, derLimits) { readAny(encoded) }

    fun decodeOwn(encoded: ByteString): EnvelopedData = successOf(Der.decode(encoded, derLimits) { readAny(encoded) })

    fun decodeEncrypted(encoded: ByteString): EncryptedData? =
        Der.decodeOrNull(encoded, derLimits) { readEncrypted(encoded) }

    fun decodeOwnEncrypted(encoded: ByteString): EncryptedData =
        successOf(Der.decode(encoded, derLimits) { readEncrypted(encoded) })

    private fun DerReader.readAny(encoded: ByteString): EnvelopedData = readSequence {
        val type = readObjectIdentifier()
        val isAuthenticated = type == ContentTypes.AuthEnvelopedData
        if (!isAuthenticated && type != ContentTypes.EnvelopedData) malformed("enveloped data")
        readExplicit(0) { readEnveloped(isAuthenticated, encoded) }
    }

    private fun DerReader.readEncrypted(encoded: ByteString): EncryptedData =
        readContentInfo(ContentTypes.EncryptedData) {
            readSequence {
                val version = readInt(0..ENCRYPTED_MAXIMUM_VERSION)
                val content = readEncryptedContent(isAuthenticated = false)
                val unprotected = takeIf {
                    isNext(
                        FIRST,
                    )
                }?.readAttributeSet(FIRST, limits.maximumAttributes, isSorted = false)
                EncryptedData(
                    version = version,
                    contentType = content.contentType,
                    algorithm = content.algorithm,
                    encryptedContent = content.ciphertext,
                    unprotectedAttributes = unprotected?.attributes.orEmpty(),
                    encoded = encoded,
                )
            }
        }

    fun encodeEnveloped(envelope: Envelope): ByteString = Der.encode {
        sequence {
            val types = listOf(ContentTypes.EnvelopedData, ContentTypes.AuthEnvelopedData)
            val isAuthenticated = envelope.algorithm.encryption.isAuthenticated
            objectIdentifier(types[isAuthenticated.compareTo(false)])
            explicit(0) {
                sequence {
                    integer(envelope.version.toLong())
                    sortedSet(Tag.Set, envelope.recipients)
                    writeEncryptedContent(envelope.contentType, envelope.algorithm, envelope.ciphertext)
                    envelope.authenticated?.let { attributes -> writeAttributes(FIRST, attributes) }
                    envelope.mac?.let { mac -> octetString(mac) }
                }
            }
        }
    }

    fun encodeEncrypted(
        contentType: ObjectIdentifier,
        algorithm: ContentAlgorithm,
        ciphertext: ByteString,
    ): ByteString = Der.encode {
        sequence {
            objectIdentifier(ContentTypes.EncryptedData)
            explicit(0) {
                sequence {
                    integer(0)
                    writeEncryptedContent(contentType, algorithm, ciphertext)
                }
            }
        }
    }

    private fun DerReader.readEnveloped(isAuthenticated: Boolean, encoded: ByteString): EnvelopedData = readSequence {
        val version = readInt(0..MAXIMUM_VERSION)
        readOptional(Tag.context(number = 0, isConstructed = true))
        val recipients = readSetElements(Tag.Set, limits.maximumRecipients, isSorted = false).map { element ->
            RecipientCodec.recipientOf(element, limits.maximumRecipients)
        }
        if (recipients.isEmpty()) malformed("a recipient")
        val content = readEncryptedContent(isAuthenticated)
        val authenticated = takeIf {
            isAuthenticated &&
                isNext(
                    FIRST,
                )
        }?.readAttributeSet(FIRST, limits.maximumAttributes, isSorted = true)
        val mac = when (isAuthenticated) {
            true -> readOctetString()
            false -> ByteString()
        }
        val unprotectedTag = listOf(FIRST, SECOND)[isAuthenticated.compareTo(false)]
        val unprotected = takeIf {
            isNext(
                unprotectedTag,
            )
        }?.readAttributeSet(unprotectedTag, limits.maximumAttributes, isSorted = false)
        val parts = EnvelopedParts(
            version = version,
            isAuthenticated = isAuthenticated,
            recipients = recipients,
            contentType = content.contentType,
            algorithm = content.algorithm,
            encryptedContent = content.ciphertext,
            authenticated = authenticated,
            mac = mac,
            unprotected = unprotected?.attributes.orEmpty(),
            encoded = encoded,
        )
        EnvelopedData(parts)
    }

    private fun DerReader.readEncryptedContent(isAuthenticated: Boolean): EncryptedContent = readSequence {
        val contentType = readObjectIdentifier()
        val algorithm = readContentAlgorithm()?.takeIf { found -> found.encryption.isAuthenticated == isAuthenticated }
        val ciphertext = readOptional(CONTENT)?.content
        val size = ciphertext?.size ?: 0
        if (size > limits.maximumContentBytes + BLOCK) {
            limited(
                "a content of at most ${limits.maximumContentBytes} bytes",
            )
        }
        EncryptedContent(contentType = contentType, algorithm = algorithm, ciphertext = ciphertext)
    }

    private fun DerWriter.writeEncryptedContent(
        contentType: ObjectIdentifier,
        algorithm: ContentAlgorithm,
        ciphertext: ByteString,
    ) {
        sequence {
            objectIdentifier(contentType)
            writeContentAlgorithm(algorithm)
            octetString(ciphertext, CONTENT)
        }
    }

    private fun <T> DerReader.readContentInfo(type: ObjectIdentifier, block: DerReader.() -> T): T =
        with(SignedCodec) { readContentInfo(type, block) }

    private data class EncryptedContent(
        val contentType: ObjectIdentifier,
        val algorithm: ContentAlgorithm?,
        val ciphertext: ByteString?,
    )

    data class Envelope(
        val version: Int,
        val recipients: List<ByteString>,
        val contentType: ObjectIdentifier,
        val algorithm: ContentAlgorithm,
        val ciphertext: ByteString,
        val authenticated: List<Attribute>?,
        val mac: ByteString?,
    )
}
