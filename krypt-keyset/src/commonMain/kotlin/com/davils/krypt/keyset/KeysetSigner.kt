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
import com.davils.krypt.primitive.key.PrivateKey
import kotlinx.io.bytestring.ByteString

/**
 * Signs with the primary key of a [Keyset] of [KeyPurpose.Signing].
 *
 * A signature is a version byte, the eight bytes of the key id and the signature of the default algorithm of the key,
 * in DER for ECDSA. The object is safe to share between threads.
 *
 * @property keyset the private key set.
 * @since 1.0.0
 */
public class KeysetSigner internal constructor(private val crypto: Crypto, public val keyset: Keyset) {
    private val primary: PrivateKey = keyset.usable { key -> key.privateKey }.primaryOf(keyset.primaryId)

    init {
        require(keyset.purpose is KeyPurpose.Signing) { "Only a private signing key set signs" }
    }

    /**
     * Signs [data] with the primary key.
     *
     * @param data the data.
     * @return the signature.
     * @since 1.0.0
     */
    public suspend fun sign(data: ByteString): ByteString {
        val signature = crypto.signatures.sign(key = primary, data = data)
        return Bytes.concat(Prefix.of(keyset.primaryId), signature)
    }

    /**
     * Shows the key set.
     *
     * @return the signer as text.
     * @since 1.0.0
     */
    override fun toString(): String = "KeysetSigner($keyset)"
}
