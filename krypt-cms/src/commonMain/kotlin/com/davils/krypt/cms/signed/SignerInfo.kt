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

package com.davils.krypt.cms.signed

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.Attribute
import com.davils.krypt.cms.CertificateReference
import com.davils.krypt.cms.internal.SignerParts
import com.davils.krypt.cms.internal.mapOr
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * One signer of signed data, the SignerInfo of RFC 5652, as read and not yet verified.
 *
 * @since 1.0.0
 */
public class SignerInfo internal constructor(internal val parts: SignerParts) {
    /**
     * The syntax version: 1 for a signer named by issuer and serial number, 3 for one named by key identifier.
     *
     * @since 1.0.0
     */
    public val version: Int = parts.version

    /**
     * How the signer names its certificate.
     *
     * @since 1.0.0
     */
    public val identifier: CertificateReference = parts.identifier

    /**
     * The digest of the content and of the signed attributes, or null if krypt does not know it, such as SHAKE256
     * of an Ed448 signer.
     *
     * @since 1.0.0
     */
    public val digestAlgorithm: DigestAlgorithm? = parts.digestAlgorithm

    /**
     * The signed attributes, or null if the signature covers the content directly.
     *
     * @since 1.0.0
     */
    public val signedAttributes: List<Attribute>? = parts.signed.mapOr(
        absent = { null },
        present = { signed -> signed.set.attributes },
    )

    /**
     * The signature algorithm, or null if krypt does not know it or its parameters.
     *
     * @since 1.0.0
     */
    public val signatureAlgorithm: SignatureAlgorithm? = parts.signatureAlgorithm

    /**
     * The signature value.
     *
     * @since 1.0.0
     */
    public val signature: ByteString = parts.signature

    /**
     * The unsigned attributes, such as countersignatures and time-stamp tokens; empty if there are none.
     *
     * @since 1.0.0
     */
    public val unsignedAttributes: List<Attribute> = parts.unsigned

    /**
     * The value of the content-type attribute, or null if it is absent, as in a countersignature.
     *
     * @since 1.0.0
     */
    public val contentType: ObjectIdentifier? = parts.signed?.contentType

    /**
     * The value of the message-digest attribute, or null if there are no signed attributes.
     *
     * @since 1.0.0
     */
    public val messageDigest: ByteString? = parts.signed?.messageDigest

    /**
     * The value of the signing-time attribute, or null if it is absent; the signer claims it, nobody vouches for it.
     *
     * @since 1.0.0
     */
    public val signingTime: Instant? = parts.signed?.signingTime

    /**
     * The countersignatures of RFC 5652 section 11.4 on this signer's signature, as read and not yet verified.
     *
     * @since 1.0.0
     */
    public val countersignatures: List<SignerInfo> = parts.details.countersignatures

    /**
     * The encoded time-stamp tokens of the signature-time-stamp attribute of RFC 3161, each a ContentInfo.
     *
     * @since 1.0.0
     */
    public val timeStampTokens: List<ByteString> = parts.details.timeStampTokens

    /**
     * The DER encoding of the SignerInfo.
     *
     * @since 1.0.0
     */
    public val encoded: ByteString = parts.encoded

    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] has the same encoding.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is SignerInfo && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the identifier and the algorithm.
     *
     * @return the signer as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "SignerInfo($identifier, ${signatureAlgorithm?.algorithmName.orEmpty()}, ${countersignatures.size} counter)"
}
