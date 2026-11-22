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
import com.davils.krypt.keyset.internal.primaryOf
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.exchange.HpkeSuite
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString

/**
 * Encrypts to the primary key of a [Keyset] of [KeyPurpose.Hybrid] with HPKE of RFC 9180 in base mode.
 *
 * A ciphertext is a version byte, the eight bytes of the key id, the encapsulated key and the sealed data; the version
 * and the key id are authenticated together with the associated data. The object is safe to share between threads.
 *
 * @property keyset the key set, private or public.
 * @property suite the cipher suite of the key set.
 * @since 1.0.0
 */
public class HybridEncrypter internal constructor(
    private val crypto: Crypto,
    public val keyset: Keyset,
    public val suite: HpkeSuite,
) {
    private val primary: PublicKey = keyset.usable { key -> key.publicKey }.primaryOf(keyset.primaryId)

    /**
     * Encrypts [plaintext] to the primary key.
     *
     * @param plaintext the data.
     * @param associatedData authenticated context; empty by default.
     * @param info the application context of HPKE; empty by default.
     * @return the ciphertext.
     * @since 1.0.0
     */
    public suspend fun encrypt(
        plaintext: ByteString,
        associatedData: ByteString = ByteString(),
        info: ByteString = ByteString(),
    ): ByteString {
        val prefix = Prefix.of(keyset.primaryId)
        val sealed = crypto.hpke.seal(
            suite = suite,
            recipient = primary,
            plaintext = plaintext,
            info = info,
            associatedData = Bytes.concat(prefix, associatedData),
        )
        return Bytes.concat(prefix, sealed)
    }

    /**
     * Shows the key set.
     *
     * @return the encryption as text.
     * @since 1.0.0
     */
    override fun toString(): String = "HybridEncrypter($keyset)"
}
