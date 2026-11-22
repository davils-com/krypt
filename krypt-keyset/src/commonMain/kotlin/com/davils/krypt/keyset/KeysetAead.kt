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

package com.davils.krypt.keyset

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.keyset.internal.Bytes
import com.davils.krypt.keyset.internal.Prefix
import com.davils.krypt.keyset.internal.materialOf
import com.davils.krypt.keyset.internal.primaryOf
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

/**
 * Authenticated encryption with the keys of a [Keyset]: it encrypts with the primary key and decrypts with whichever
 * enabled key the ciphertext names.
 *
 * A ciphertext is a version byte, the eight bytes of the key id, the nonce and the sealed data; the version and the
 * key id are authenticated together with the associated data. A fresh random nonce is drawn for every message, so
 * one key should seal at most 2^32 messages with AES-GCM; rotate the key set before that.
 *
 * The object is safe to share between threads.
 *
 * @property keyset the key set.
 * @property algorithm the AEAD of the key set.
 * @since 1.0.0
 */
public class KeysetAead internal constructor(
    private val crypto: Crypto,
    public val keyset: Keyset,
    public val algorithm: AeadAlgorithm,
) {
    private val secrets: List<Pair<KeyId, SecretKey>> = keyset.usable { key -> key.secret }
    private val primary: SecretKey = secrets.primaryOf(keyset.primaryId)

    init {
        val purpose = keyset.purpose
        require(purpose is KeyPurpose.Aead && purpose.algorithm == algorithm) {
            "A key set of $purpose does not encrypt with $algorithm"
        }
    }

    /**
     * Encrypts [plaintext] with the primary key.
     *
     * @param plaintext the data.
     * @param associatedData authenticated context that is not encrypted, such as the id of a record; empty by default.
     * @return the ciphertext.
     * @since 1.0.0
     */
    public suspend fun encrypt(plaintext: ByteString, associatedData: ByteString = ByteString()): ByteString {
        val prefix = Prefix.of(keyset.primaryId)
        val nonce = ByteString(crypto.environment.random.bytes(algorithm.nonceBytes))
        val sealed = crypto.aead.encrypt(
            key = primary,
            nonce = nonce,
            plaintext = plaintext,
            associatedData = Bytes.concat(prefix, associatedData),
            algorithm = algorithm,
        )
        return Bytes.concat(prefix, nonce, sealed)
    }

    /**
     * Decrypts a ciphertext of [encrypt].
     *
     * @param ciphertext the ciphertext, possibly from an attacker.
     * @param associatedData the authenticated context it was encrypted with.
     * @return the plaintext, or null if the ciphertext is malformed, names no enabled key or is not authentic; the
     *   reasons are not told apart.
     * @since 1.0.0
     */
    public suspend fun decrypt(ciphertext: ByteString, associatedData: ByteString = ByteString()): ByteString? {
        val parsed = Prefix.parseOrNull(ciphertext)?.takeIf { found -> found.rest.size >= algorithm.nonceBytes }
        val secret = parsed?.let { found -> secrets.materialOf(found.id) } ?: return null
        val bytes = parsed.rest.toByteArray()
        return crypto.aead.decrypt(
            key = secret,
            nonce = ByteString(data = bytes, startIndex = 0, endIndex = algorithm.nonceBytes),
            ciphertext = ByteString(data = bytes, startIndex = algorithm.nonceBytes, endIndex = bytes.size),
            associatedData = Bytes.concat(Prefix.of(parsed.id), associatedData),
            algorithm = algorithm,
        )
    }

    /**
     * Shows the key set.
     *
     * @return the encryption as text.
     * @since 1.0.0
     */
    override fun toString(): String = "KeysetAead($keyset)"
}
