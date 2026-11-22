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
import com.davils.krypt.cms.internal.ContentAlgorithm
import kotlinx.io.bytestring.ByteString

/**
 * Encrypted data of RFC 5652 in its ContentInfo: content encrypted with AES-CBC under a key the caller manages,
 * as read and not yet decrypted. It is not authenticated.
 *
 * @property version the syntax version: 0, or 2 with unprotected attributes.
 * @property contentType the type of the encrypted content.
 * @property algorithm the content encryption and its IV, or null if krypt does not know it.
 * @property encryptedContent the encrypted content, or null if it travels apart.
 * @property unprotectedAttributes the unprotected attributes; empty if there are none.
 * @property encoded the DER encoding of the ContentInfo.
 * @since 1.0.0
 */
public class EncryptedData internal constructor(
    public val version: Int,
    public val contentType: ObjectIdentifier,
    internal val algorithm: ContentAlgorithm?,
    public val encryptedContent: ByteString?,
    public val unprotectedAttributes: List<Attribute>,
    public val encoded: ByteString,
) {
    /**
     * The content encryption, or null if krypt does not know it or its parameters.
     *
     * @since 1.0.0
     */
    public val encryption: ContentEncryption? = algorithm?.encryption

    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] has the same encoding.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is EncryptedData && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the encryption.
     *
     * @return the encrypted data as text.
     * @since 1.0.0
     */
    override fun toString(): String = "EncryptedData(${encryption ?: UNKNOWN})"

    private companion object {
        const val UNKNOWN: String = "unknown"
    }
}
