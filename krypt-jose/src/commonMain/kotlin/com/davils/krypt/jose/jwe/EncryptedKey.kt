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
 * The part of a decoded JWE that belongs to one recipient.
 *
 * @property header the unprotected header of the recipient, empty in the compact serialization.
 * @property encryptedKey the encrypted content key, empty for `dir` and `ECDH-ES`.
 * @since 1.0.0
 */
public class EncryptedKey internal constructor(
    public val header: JsonValue.Object,
    public val encryptedKey: ByteString,
) {
    /**
     * Compares the header and the key.
     *
     * @param other the other object.
     * @return true if [other] is the same part.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is EncryptedKey && header == other.header && encryptedKey == other.encryptedKey

    /**
     * Hashes the key.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encryptedKey.hashCode()

    /**
     * Shows the header and the size of the key.
     *
     * @return the part as text.
     * @since 1.0.0
     */
    override fun toString(): String = "EncryptedKey($header, ${encryptedKey.size} bytes)"
}
