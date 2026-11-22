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

package com.davils.krypt.jose.jwe

import com.davils.krypt.jose.JsonValue
import kotlinx.io.bytestring.ByteString

/**
 * A decoded JWE, not decrypted yet. Nothing in it may be trusted before [Jwe.decrypt] succeeded.
 *
 * @property protectedHeader the protected header.
 * @property sharedHeader the shared unprotected header, empty in the compact serialization.
 * @property recipients the recipients, one in the compact and the flattened serialization.
 * @property iv the initialization vector.
 * @property ciphertext the ciphertext.
 * @property tag the authentication tag.
 * @property additionalData the additional authenticated data of the JSON serialization, or null.
 * @property isCompact whether the message came in the compact serialization.
 * @property protectedEncoded the protected header as it came, Base64url-encoded.
 * @property additionalEncoded the additional authenticated data as it came, or null.
 * @since 1.0.0
 */
public class JweMessage internal constructor(
    public val protectedHeader: JsonValue.Object,
    public val sharedHeader: JsonValue.Object,
    public val recipients: List<EncryptedKey>,
    public val iv: ByteString,
    public val ciphertext: ByteString,
    public val tag: ByteString,
    public val additionalData: ByteString?,
    public val isCompact: Boolean,
    internal val protectedEncoded: String,
    internal val additionalEncoded: String?,
) {
    private val values: List<Any?>
        get() = listOf(protectedEncoded, sharedHeader, recipients, iv, ciphertext, tag, additionalEncoded, isCompact)

    /**
     * Compares every part.
     *
     * @param other the other object.
     * @return true if [other] is the same message.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is JweMessage && values == other.values

    /**
     * Hashes every part.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the headers, the recipients and the size of the ciphertext.
     *
     * @return the message as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "JweMessage($protectedHeader, recipients=$recipients, ciphertext=${ciphertext.size}, compact=$isCompact)"
}
