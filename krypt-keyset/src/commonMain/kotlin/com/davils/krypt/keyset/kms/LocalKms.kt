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
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.cipher.SealedBox
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

/**
 * A [KeyManagementService] over a master [key] in the process, sealed with [algorithm].
 *
 * Use it where the master key comes from a secret store of the platform, a sealed configuration or a test. A key
 * that never leaves an HSM or a KMS is better kept there behind an implementation of [KeyManagementService].
 *
 * @param crypto the primitives.
 * @param key the master key; the caller keeps and wipes it.
 * @property keyUri the name of the master key; `local` by default.
 * @property algorithm the AEAD; AES-256-GCM by default.
 * @constructor Encrypts with [key].
 * @since 1.0.0
 */
public class LocalKms(
    private val crypto: Crypto,
    private val key: SecretKey,
    override val keyUri: String = DEFAULT_KEY_URI,
    public val algorithm: AeadAlgorithm = AeadAlgorithm.Aes256Gcm,
) : KeyManagementService {
    /**
     * Seals [plaintext] with a fresh nonce.
     *
     * @param plaintext the secret.
     * @param associatedData authenticated context.
     * @return the nonce followed by the sealed data.
     * @since 1.0.0
     */
    override suspend fun encrypt(plaintext: SecretBytes, associatedData: ByteString): ByteString {
        val data = plaintext.reveal { bytes -> ByteString(bytes) }
        val box = crypto.aead.seal(key = key, plaintext = data, associatedData = associatedData, algorithm = algorithm)
        return box.encoded
    }

    /**
     * Opens a ciphertext of [encrypt].
     *
     * @param ciphertext the ciphertext.
     * @param associatedData the authenticated context.
     * @return the secret, or null if the ciphertext is malformed or not authentic.
     * @since 1.0.0
     */
    override suspend fun decrypt(ciphertext: ByteString, associatedData: ByteString): SecretBytes? {
        val box = SealedBox.decodeOrNull(ciphertext, algorithm) ?: return null
        val opened = crypto.aead.open(key = key, box = box, associatedData = associatedData, algorithm = algorithm)
        return opened?.let { bytes -> SecretBytes.copyOf(bytes) }
    }

    /**
     * Shows the name of the key.
     *
     * @return the service as text.
     * @since 1.0.0
     */
    override fun toString(): String = "LocalKms($keyUri, ${algorithm.algorithmName})"

    private companion object {
        const val DEFAULT_KEY_URI: String = "local"
    }
}
