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

import com.davils.krypt.keyset.internal.Prefix
import com.davils.krypt.keyset.internal.materialOf
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.Verification
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString

/**
 * Verifies signatures of a [KeysetSigner] with the enabled key each signature names.
 *
 * The object is safe to share between threads.
 *
 * @property keyset the key set, private or public.
 * @since 1.0.0
 */
public class KeysetVerifier internal constructor(private val crypto: Crypto, public val keyset: Keyset) {
    private val publicKeys: List<Pair<KeyId, PublicKey>> = keyset.usable { key -> key.publicKey }

    init {
        require(keyset.purpose is KeyPurpose.Signing) { "Only a signing key set verifies" }
    }

    /**
     * Verifies [signature] of [data].
     *
     * @param data the data.
     * @param signature the signature, possibly from an attacker.
     * @return [Verification.Valid] if an enabled key of the key set signed [data].
     * @since 1.0.0
     */
    public suspend fun verify(data: ByteString, signature: ByteString): Verification {
        val parsed = Prefix.parseOrNull(signature)
        val public = parsed?.let { found -> publicKeys.materialOf(found.id) } ?: return Verification.Invalid
        return crypto.signatures.verify(key = public, data = data, signature = parsed.rest)
    }

    /**
     * Shows the key set.
     *
     * @return the verifier as text.
     * @since 1.0.0
     */
    override fun toString(): String = "KeysetVerifier($keyset)"
}
