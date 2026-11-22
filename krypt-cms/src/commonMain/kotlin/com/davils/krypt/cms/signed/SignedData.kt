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
import com.davils.krypt.cms.internal.SignedParts
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.crl.RevocationList
import kotlinx.io.bytestring.ByteString

/**
 * Signed data of RFC 5652 in its ContentInfo, as read and not yet verified.
 *
 * @since 1.0.0
 */
public class SignedData internal constructor(internal val parts: SignedParts) {
    /**
     * The syntax version: 1, or 3 if a signer is named by key identifier or the content is not id-data.
     *
     * @since 1.0.0
     */
    public val version: Int = parts.version

    /**
     * The type of the encapsulated content, such as [com.davils.krypt.cms.ContentTypes.Data].
     *
     * @since 1.0.0
     */
    public val contentType: ObjectIdentifier = parts.contentType

    /**
     * The encapsulated content, or null if the signature is detached from it.
     *
     * @since 1.0.0
     */
    public val content: ByteString? = parts.content

    /**
     * True if the content travels apart from the signature.
     *
     * @since 1.0.0
     */
    public val isDetached: Boolean get() = content == null

    /**
     * The certificates the message carries, possibly from an attacker; none of them is trusted by being here.
     *
     * @since 1.0.0
     */
    public val certificates: List<Certificate> = parts.certificates

    /**
     * The revocation lists the message carries, not verified.
     *
     * @since 1.0.0
     */
    public val revocationLists: List<RevocationList> = parts.revocationLists

    /**
     * The signers, in the DER order of their encodings.
     *
     * @since 1.0.0
     */
    public val signers: List<SignerInfo> = parts.signers

    /**
     * The DER encoding of the ContentInfo.
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
    override fun equals(other: Any?): Boolean = other is SignedData && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the content type and the number of signers.
     *
     * @return the signed data as text.
     * @since 1.0.0
     */
    override fun toString(): String = "SignedData(${contentType.dotted}, ${signers.size} signers, detached=$isDetached)"
}
