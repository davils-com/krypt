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

package com.davils.krypt.x509

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.extension.Extensions
import com.davils.krypt.x509.internal.TbsParts
import com.davils.krypt.x509.name.DistinguishedName
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * An X.509 certificate, read strictly by RFC 5280 and kept with its encoding.
 *
 * A certificate read is not yet trusted: its signature, its validity and its path are checked by
 * [com.davils.krypt.x509.path.PathValidator]. Two certificates are equal when their encodings are.
 *
 * @property signature the signature.
 * @since 1.0.0
 */
public class Certificate internal constructor(parts: TbsParts, public val signature: ByteString) {
    /**
     * The DER encoding.
     *
     * @since 1.0.0
     */
    public val encoded: ByteString = parts.encoded

    /**
     * The version, 1, 2 or 3.
     *
     * @since 1.0.0
     */
    public val version: Int = parts.version

    /**
     * The serial number.
     *
     * @since 1.0.0
     */
    public val serialNumber: DerInteger = parts.serial

    /**
     * The algorithm of the signature, or null if krypt does not know it, such as SHA-1.
     *
     * @since 1.0.0
     */
    public val signatureAlgorithm: SignatureAlgorithm? = parts.algorithm

    /**
     * The name of the issuer.
     *
     * @since 1.0.0
     */
    public val issuer: DistinguishedName = parts.issuer

    /**
     * The start of the validity.
     *
     * @since 1.0.0
     */
    public val notBefore: Instant = parts.notBefore

    /**
     * The end of the validity, inclusive.
     *
     * @since 1.0.0
     */
    public val notAfter: Instant = parts.notAfter

    /**
     * The name of the subject.
     *
     * @since 1.0.0
     */
    public val subject: DistinguishedName = parts.subject

    /**
     * The DER encoding of the public key.
     *
     * @since 1.0.0
     */
    public val subjectPublicKeyInfo: ByteString = parts.spki

    /**
     * The public key, or null if krypt cannot read it or the policy forbids it.
     *
     * @since 1.0.0
     */
    public val publicKey: PublicKey? = parts.publicKey

    /**
     * The extensions.
     *
     * @since 1.0.0
     */
    public val extensions: Extensions = parts.extensions

    /**
     * The DER encoding of the part that is signed.
     *
     * @since 1.0.0
     */
    public val tbs: ByteString = parts.tbs

    /**
     * Whether the subject is a certificate authority by its basic constraints.
     *
     * @since 1.0.0
     */
    public val isCa: Boolean get() = extensions.basicConstraints?.isCa == true

    /**
     * Whether the issuer and the subject have the same name, as for a root or a re-keyed authority.
     *
     * @since 1.0.0
     */
    public val isSelfIssued: Boolean get() = issuer == subject

    /**
     * Tells whether [at] lies within the validity, both ends included.
     *
     * @param at the time.
     * @return true if the certificate is valid at [at].
     * @since 1.0.0
     */
    public fun isValidAt(at: Instant): Boolean = at in notBefore..notAfter

    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] is the same certificate.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is Certificate && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the subject, the issuer, the serial number and the end of the validity.
     *
     * @return the certificate as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "Certificate(subject=$subject, issuer=$issuer, serial=$serialNumber, notAfter=$notAfter)"
}
