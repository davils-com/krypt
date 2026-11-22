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

import com.davils.krypt.cms.CertificateReference
import com.davils.krypt.cms.internal.ParsedRecipient
import kotlinx.io.bytestring.ByteString

/**
 * One recipient of enveloped data as read: its kind and how it names its key.
 *
 * @property parsed what krypt read of the recipient.
 * @property encoded the DER encoding of the RecipientInfo.
 * @since 1.0.0
 */
public class RecipientInfo internal constructor(internal val parsed: ParsedRecipient, public val encoded: ByteString) {
    /**
     * The kind of recipient.
     *
     * @since 1.0.0
     */
    public val type: RecipientType = when (parsed) {
        is ParsedRecipient.Transport -> RecipientType.KeyTransport
        is ParsedRecipient.Agreement -> RecipientType.KeyAgreement
        is ParsedRecipient.Kek -> RecipientType.Kek
        is ParsedRecipient.Password -> RecipientType.Password
        is ParsedRecipient.Kem -> RecipientType.Kem
        is ParsedRecipient.Unsupported -> parsed.type
    }

    /**
     * The certificates this recipient names: one for key transport and KEM, one per recipient key for key
     * agreement, none otherwise.
     *
     * @since 1.0.0
     */
    public val references: List<CertificateReference> = when (parsed) {
        is ParsedRecipient.Transport -> listOf(parsed.reference)
        is ParsedRecipient.Agreement -> parsed.keys.map { (reference, _) -> reference }
        is ParsedRecipient.Kem -> listOf(parsed.reference)
        is ParsedRecipient.Kek -> emptyList()
        is ParsedRecipient.Password -> emptyList()
        is ParsedRecipient.Unsupported -> parsed.references
    }

    /**
     * The identifier of the key-encryption key of a KEK recipient, or null for other kinds.
     *
     * @since 1.0.0
     */
    public val keyIdentifier: ByteString? = when (parsed) {
        is ParsedRecipient.Kek -> parsed.keyIdentifier
        is ParsedRecipient.Unsupported -> parsed.keyIdentifier
        is ParsedRecipient.Transport -> null
        is ParsedRecipient.Agreement -> null
        is ParsedRecipient.Password -> null
        is ParsedRecipient.Kem -> null
    }

    /**
     * True if krypt knows every algorithm of this recipient and can open it with a matching credential.
     *
     * @since 1.0.0
     */
    public val isSupported: Boolean get() = parsed !is ParsedRecipient.Unsupported

    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] has the same encoding.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is RecipientInfo && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the kind and the references.
     *
     * @return the recipient as text.
     * @since 1.0.0
     */
    override fun toString(): String = "RecipientInfo($type, $references)"
}
