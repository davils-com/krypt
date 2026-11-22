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

package com.davils.krypt.x509.request

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.extension.Extensions
import com.davils.krypt.x509.internal.RequestParts
import com.davils.krypt.x509.name.DistinguishedName
import kotlinx.io.bytestring.ByteString

/**
 * A certification request of PKCS #10 (RFC 2986): the subject asks for a certificate of its public key and proves
 * that it holds the private key by signing the request with it.
 *
 * Everything in a request comes from the subject; an authority decides what it puts into the certificate.
 *
 * @property encoded the DER encoding.
 * @property subject the name the subject asks for.
 * @property subjectPublicKeyInfo the DER encoding of the public key.
 * @property publicKey the public key, or null if krypt cannot read it or the policy forbids it.
 * @property requestedExtensions the extensions the subject asks for.
 * @property attributeTypes the types of every attribute of the request.
 * @property signatureAlgorithm the algorithm of the signature, or null if krypt does not know it.
 * @property info the DER encoding of the part that is signed.
 * @property signature the signature.
 * @since 1.0.0
 */
public class CertificationRequest private constructor(
    public val encoded: ByteString,
    public val subject: DistinguishedName,
    public val subjectPublicKeyInfo: ByteString,
    public val publicKey: PublicKey?,
    public val requestedExtensions: Extensions,
    public val attributeTypes: List<ObjectIdentifier>,
    public val signatureAlgorithm: SignatureAlgorithm?,
    public val info: ByteString,
    public val signature: ByteString,
) {
    internal constructor(parts: RequestParts) : this(
        encoded = parts.encoded,
        subject = parts.subject,
        subjectPublicKeyInfo = parts.subjectPublicKeyInfo,
        publicKey = parts.publicKey,
        requestedExtensions = parts.requestedExtensions,
        attributeTypes = parts.attributeTypes,
        signatureAlgorithm = parts.signatureAlgorithm,
        info = parts.info,
        signature = parts.signature,
    )

    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] is the same request.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CertificationRequest && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the subject.
     *
     * @return the request as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CertificationRequest(subject=$subject)"
}
