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

package com.davils.krypt.x509.request

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerLimits
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.pem.Pem
import com.davils.krypt.asn1.readInt
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.Verification
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.AlgorithmIdentifiers
import com.davils.krypt.x509.AlgorithmIdentifiers.readSignatureAlgorithm
import com.davils.krypt.x509.X509Failure
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.Extensions
import com.davils.krypt.x509.internal.CertificateCodec.readExtensionList
import com.davils.krypt.x509.internal.ExtensionWrites.writeExtensions
import com.davils.krypt.x509.internal.NameCodec.readName
import com.davils.krypt.x509.internal.SignatureChecks
import com.davils.krypt.x509.internal.X509Oids
import kotlinx.io.bytestring.ByteString

private const val LABEL: String = "CERTIFICATE REQUEST"
private const val ATTRIBUTES: Int = 0
private const val VERSION: Int = 0

/**
 * Reads, writes, verifies and creates certification requests of PKCS #10.
 *
 * The object holds no key and is safe to share between threads.
 *
 * @property crypto the primitives and their policy.
 * @property limits the limits of reading.
 * @since 1.0.0
 */
public class CertificationRequests(public val crypto: Crypto, public val limits: X509Limits = X509Limits.Default) {
    /**
     * Reads a request in DER.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the request, or [X509Failure.Malformed].
     * @since 1.0.0
     */
    public fun decode(encoded: ByteString): Outcome<CertificationRequest, X509Failure> {
        val request = Der.decodeOrNull(encoded, DerLimits(maximumBytes = limits.maximumBytes)) { readRequest(encoded) }
            ?: return Outcome.Failure(X509Failure.Malformed)
        return Outcome.Success(request)
    }

    /**
     * Reads the first request of a PEM text.
     *
     * @param text the text, possibly from an attacker.
     * @return the request, or [X509Failure.Malformed].
     * @since 1.0.0
     */
    public fun decodePem(text: String): Outcome<CertificationRequest, X509Failure> {
        val decoded = Pem.decode(text)
        val blocks = decoded.getOrNull().orEmpty()
        val block = blocks.firstOrNull { found -> found.label == LABEL } ?: return Outcome.Failure(
            X509Failure.Malformed,
        )
        return decode(block.bytes)
    }

    /**
     * Writes [request] in PEM.
     *
     * @param request the request.
     * @return the PEM text.
     * @since 1.0.0
     */
    public fun encodePem(request: CertificationRequest): String = Pem.encode(label = LABEL, bytes = request.encoded)

    /**
     * Verifies that the subject of [request] holds its private key.
     *
     * @param request the request.
     * @return [Verification.Valid] if the request is signed with its own key by an algorithm the policy permits.
     * @since 1.0.0
     */
    public suspend fun verify(request: CertificationRequest): Verification {
        val key = request.publicKey ?: return Verification.Invalid
        return SignatureChecks.verify(
            crypto = crypto,
            algorithm = request.signatureAlgorithm,
            key = key,
            data = request.info,
            signature = request.signature,
        )
    }

    /**
     * Creates a request for the public key of [signer], signed with its private key.
     *
     * @param signer the signer of the subject.
     * @param block describes the request.
     * @return the request.
     * @since 1.0.0
     */
    public suspend fun create(signer: Signer, block: CertificationRequestBuilder.() -> Unit): CertificationRequest {
        val builder = CertificationRequestBuilder()
        builder.block()
        val info = Der.encode {
            sequence {
                integer(VERSION.toLong())
                raw(builder.subject.encoded)
                raw(signer.publicKey.encoded)
                constructed(Tag.context(number = ATTRIBUTES, isConstructed = true)) {
                    writeExtensionRequest(builder.extensions)
                }
            }
        }
        val signature = signer.sign(info)
        val encoded = Der.encode {
            sequence {
                raw(info)
                raw(AlgorithmIdentifiers.encode(signer.algorithm))
                bitString(BitString(signature))
            }
        }
        return checkNotNull(decode(encoded).getOrNull()) { "The created request is not valid" }
    }

    /**
     * Shows the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CertificationRequests($limits)"

    private fun DerWriter.writeExtensionRequest(extensions: List<Extension>) {
        if (extensions.isEmpty()) return
        sequence {
            objectIdentifier(X509Oids.EXTENSION_REQUEST)
            setOf { writeExtensions(extensions) }
        }
    }

    private fun DerReader.readRequest(encoded: ByteString): CertificationRequest = readSequence {
        val info = readElement(Tag.Sequence)
        val algorithm = readSignatureAlgorithm()
        val signature = readBitString()
        if (signature.unusedBits != 0) refuse(DerFailure.InvalidValue, "a signature of whole bytes")
        val inner = info.reader()
        inner.readInt(VERSION..VERSION)
        val subject = inner.readName(limits.maximumNames)
        val spki = inner.readElement(Tag.Sequence).encoded
        val attributes = inner.readConstructed(Tag.context(number = ATTRIBUTES, isConstructed = true)) {
            readAttributes()
        }
        if (!inner.isExhausted) inner.refuse(DerFailure.InvalidValue, "the end of the request")
        CertificationRequest(
            encoded = encoded,
            subject = subject,
            subjectPublicKeyInfo = spki,
            publicKey = crypto.keys.decodePublic(spki).getOrNull(),
            requestedExtensions = Extensions(attributes.second, limits.maximumNames),
            attributeTypes = attributes.first,
            signatureAlgorithm = algorithm,
            info = info.encoded,
            signature = signature.bytes,
        )
    }

    private fun DerReader.readAttributes(): Pair<List<ObjectIdentifier>, List<Extension>> {
        val types = mutableListOf<ObjectIdentifier>()
        var extensions: List<Extension> = emptyList()
        while (!isExhausted) {
            if (types.size >= limits.maximumExtensions) {
                refuse(
                    DerFailure.LimitExceeded,
                    "at most ${limits.maximumExtensions} attributes",
                )
            }
            readSequence {
                val type = readObjectIdentifier()
                types += type
                val isRequest = type == X509Oids.EXTENSION_REQUEST
                readSet {
                    if (isRequest) extensions = readExtensionList(limits.maximumExtensions)
                    while (!isExhausted) readElement()
                }
            }
        }
        if (types.toSet().size != types.size) refuse(DerFailure.InvalidValue, "distinct attributes")
        return types to extensions
    }
}
