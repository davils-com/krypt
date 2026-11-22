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
 * A COSE_recipient of RFC 9052 section 5.1: how one recipient obtains the content key of a [CoseEncrypt] or a
 * [CoseMac], possibly through recipients of its own.
 *
 * Values of this type come from [Cose], which creates and decodes them; they are immutable and safe to share
 * between threads.
 *
 * @property protectedHeaders the protected header parameters.
 * @property unprotectedHeaders the unprotected header parameters.
 * @property ciphertext the encrypted key, empty for direct and direct key agreement, or null.
 * @property recipients the recipients of the key of this layer, usually none.
 * @property protectedEncoding the serialized protected header parameters as they are covered.
 * @since 1.0.0
 */
public class CoseRecipient internal constructor(
    public val protectedHeaders: CoseHeaders,
    public val unprotectedHeaders: CoseHeaders,
    public val ciphertext: ByteString?,
    public val recipients: List<CoseRecipient>,
    public val protectedEncoding: ByteString,
) {
    private val values: List<Any?> get() = listOf(protectedEncoding, unprotectedHeaders, ciphertext, recipients)

    internal fun body(): List<CborItem> {
        val nested = CborArray(recipients.map { recipient -> CborArray(recipient.body()) })
        val layers = listOfNotNull(nested.takeIf { recipients.isNotEmpty() })
        return Bodies.headers(protectedEncoding, unprotectedHeaders) + Bodies.optional(ciphertext) + layers
    }

    /**
     * Compares the encoded protected header parameters, the unprotected ones and every field.
     *
     * @param other the other object.
     * @return true if [other] is the same structure.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CoseRecipient && values == other.values

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
        name = "CoseRecipient",
        protectedHeaders = protectedHeaders,
        unprotectedHeaders = unprotectedHeaders,
        rest = "ciphertext=${Bodies.size(ciphertext)}, " +
            "recipients=$recipients",
    )
}
