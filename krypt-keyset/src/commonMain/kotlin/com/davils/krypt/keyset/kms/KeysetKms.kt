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

package com.davils.krypt.keyset.kms

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.keyset.KeysetAead
import kotlinx.io.bytestring.ByteString

/**
 * A [KeyManagementService] over the authenticated encryption of a key set, so that the key encryption key can be
 * rotated: new secrets are encrypted with the primary key, old ones are still decrypted with the key that encrypted
 * them.
 *
 * @param aead the encryption of the key set.
 * @property keyUri the name of the key set.
 * @constructor Encrypts with [aead].
 * @since 1.0.0
 */
public class KeysetKms(private val aead: KeysetAead, override val keyUri: String) : KeyManagementService {
    /**
     * Encrypts [plaintext] with the primary key.
     *
     * @param plaintext the secret.
     * @param associatedData authenticated context.
     * @return the ciphertext.
     * @since 1.0.0
     */
    override suspend fun encrypt(plaintext: SecretBytes, associatedData: ByteString): ByteString {
        val data = plaintext.reveal { bytes -> ByteString(bytes) }
        return aead.encrypt(plaintext = data, associatedData = associatedData)
    }

    /**
     * Decrypts a ciphertext of [encrypt] with the key it names.
     *
     * @param ciphertext the ciphertext.
     * @param associatedData the authenticated context.
     * @return the secret, or null if the ciphertext is malformed, names no enabled key or is not authentic.
     * @since 1.0.0
     */
    override suspend fun decrypt(ciphertext: ByteString, associatedData: ByteString): SecretBytes? {
        val opened = aead.decrypt(ciphertext = ciphertext, associatedData = associatedData)
        return opened?.let { bytes -> SecretBytes.copyOf(bytes) }
    }

    /**
     * Shows the name of the key set.
     *
     * @return the service as text.
     * @since 1.0.0
     */
    override fun toString(): String = "KeysetKms($keyUri)"
}
