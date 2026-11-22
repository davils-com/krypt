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

package com.davils.krypt.cose

import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.internal.Bodies
import kotlinx.io.bytestring.ByteString

/**
 * A COSE_Encrypt of RFC 9052 section 5.1: encrypted content with the recipients of its key.
 *
 * Values of this type come from [Cose], which creates and decodes them; they are immutable and safe to share
 * between threads.
 *
 * @property protectedHeaders the protected header parameters.
 * @property unprotectedHeaders the unprotected header parameters.
 * @property ciphertext the ciphertext with its tag, or null if it is detached and travels apart.
 * @property recipients the recipients of the content key, at least one.
 * @property protectedEncoding the serialized protected header parameters as they are covered.
 * @since 1.0.0
 */
public class CoseEncrypt internal constructor(
    public override val protectedHeaders: CoseHeaders,
    public override val unprotectedHeaders: CoseHeaders,
    public val ciphertext: ByteString?,
    public val recipients: List<CoseRecipient>,
    public override val protectedEncoding: ByteString,
) : CoseMessage() {
    /**
     * Always [CoseMessageType.Encrypt].
     *
     * @since 1.0.0
     */
    override val type: CoseMessageType get() = CoseMessageType.Encrypt

    private val values: List<Any?> get() = listOf(protectedEncoding, unprotectedHeaders, ciphertext, recipients)

    override fun body(): List<CborItem> = Bodies.headers(protectedEncoding, unprotectedHeaders) +
        listOf(
            Bodies.optional(ciphertext),
            CborArray(recipients.map { recipient -> CborArray(recipient.body()) }),
        )

    /**
     * Compares the encoded protected header parameters, the unprotected ones and every field.
     *
     * @param other the other object.
     * @return true if [other] is the same structure.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CoseEncrypt && values == other.values

    /**
     * Hashes every field.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the header parameters and the sizes of the fields.
     *
     * @return the structure as text.
     * @since 1.0.0
     */
    override fun toString(): String = Bodies.describe(
        name = "CoseEncrypt",
        protectedHeaders = protectedHeaders,
        unprotectedHeaders = unprotectedHeaders,
        rest = "ciphertext=${Bodies.size(ciphertext)}, " +
            "recipients=$recipients",
    )
}
