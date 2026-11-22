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

import com.davils.krypt.keyset.internal.Bytes
import com.davils.krypt.keyset.internal.Prefix
import com.davils.krypt.keyset.internal.materialOf
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.exchange.HpkeSuite
import com.davils.krypt.primitive.key.PrivateKey
import kotlinx.io.bytestring.ByteString

/**
 * Decrypts what a [HybridEncrypter] encrypted, with the enabled private key the ciphertext names.
 *
 * The object is safe to share between threads.
 *
 * @property keyset the private key set.
 * @property suite the cipher suite of the key set.
 * @since 1.0.0
 */
public class HybridDecrypter internal constructor(
    private val crypto: Crypto,
    public val keyset: Keyset,
    public val suite: HpkeSuite,
) {
    private val privateKeys: List<Pair<KeyId, PrivateKey>> = keyset.usable { key -> key.privateKey }

    init {
        val purpose = keyset.purpose
        require(purpose is KeyPurpose.Hybrid && purpose.suite == suite && !keyset.isPublic) {
            "A key set of $purpose does not decrypt with $suite"
        }
    }

    /**
     * Decrypts [ciphertext].
     *
     * @param ciphertext the ciphertext, possibly from an attacker.
     * @param associatedData the authenticated context it was encrypted with.
     * @param info the application context of HPKE it was encrypted with.
     * @return the plaintext, or null if the ciphertext is malformed, names no enabled key or is not authentic.
     * @since 1.0.0
     */
    public suspend fun decrypt(
        ciphertext: ByteString,
        associatedData: ByteString = ByteString(),
        info: ByteString = ByteString(),
    ): ByteString? {
        val parsed = Prefix.parseOrNull(ciphertext)
        val private = parsed?.let { found -> privateKeys.materialOf(found.id) } ?: return null
        return crypto.hpke.open(
            suite = suite,
            recipient = private,
            sealed = parsed.rest,
            info = info,
            associatedData = Bytes.concat(Prefix.of(parsed.id), associatedData),
        )
    }

    /**
     * Shows the key set.
     *
     * @return the decryption as text.
     * @since 1.0.0
     */
    override fun toString(): String = "HybridDecrypter($keyset)"
}
