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

package com.davils.krypt.cms.enveloped

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.Attribute
import com.davils.krypt.cms.internal.EnvelopedParts
import kotlinx.io.bytestring.ByteString

/**
 * Enveloped data of RFC 5652 or authenticated-enveloped data of RFC 5083 in its ContentInfo, as read and not yet
 * decrypted.
 *
 * EnvelopedData with AES-CBC is not authenticated: a change of the ciphertext goes unnoticed and a decryption that
 * reports its padding opens an oracle, which krypt narrows with one failure for everything; krypt decrypts it only
 * with `isUnauthenticatedCbcAllowed`. Prefer AuthEnvelopedData with AES-GCM.
 *
 * @since 1.0.0
 */
public class EnvelopedData internal constructor(internal val parts: EnvelopedParts) {
    /**
     * The syntax version.
     *
     * @since 1.0.0
     */
    public val version: Int = parts.version

    /**
     * True for AuthEnvelopedData of RFC 5083, false for EnvelopedData.
     *
     * @since 1.0.0
     */
    public val isAuthenticated: Boolean = parts.isAuthenticated

    /**
     * The recipients, in the DER order of their encodings.
     *
     * @since 1.0.0
     */
    public val recipients: List<RecipientInfo> = parts.recipients

    /**
     * The type of the encrypted content.
     *
     * @since 1.0.0
     */
    public val contentType: ObjectIdentifier = parts.contentType

    /**
     * The content encryption, or null if krypt does not know it or its parameters.
     *
     * @since 1.0.0
     */
    public val encryption: ContentEncryption? = parts.algorithm?.encryption

    /**
     * The encrypted content, without the tag of AES-GCM, or null if it travels apart.
     *
     * @since 1.0.0
     */
    public val encryptedContent: ByteString? = parts.encryptedContent

    /**
     * The authenticated attributes of AuthEnvelopedData, or null if there are none.
     *
     * @since 1.0.0
     */
    public val authenticatedAttributes: List<Attribute>? = parts.authenticated?.attributes

    /**
     * The unprotected attributes of EnvelopedData or the unauthenticated ones of AuthEnvelopedData; empty if there
     * are none. Anybody may have changed them.
     *
     * @since 1.0.0
     */
    public val unprotectedAttributes: List<Attribute> = parts.unprotected

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
    override fun equals(other: Any?): Boolean = other is EnvelopedData && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the kind, the encryption and the number of recipients.
     *
     * @return the enveloped data as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "EnvelopedData(authenticated=$isAuthenticated, ${encryption ?: UNKNOWN}, ${recipients.size} recipients)"

    private companion object {
        const val UNKNOWN: String = "unknown"
    }
}
