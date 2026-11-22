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

package com.davils.krypt.primitive.internal

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.primitive.key.KeyPair
import com.davils.krypt.primitive.key.PrivateKey
import kotlinx.io.bytestring.ByteString
import java.security.PrivateKey as JcaPrivateKey
import java.security.PublicKey as JcaPublicKey

internal object JcaKeys {
    private fun parse(encoding: SecretBytes): PrivateKey? = encoding.use { owned ->
        val decoded = PrivateKey.decode(owned)
        decoded.getOrNull()
    }

    fun pairOf(publicKey: JcaPublicKey, privateKey: JcaPrivateKey): KeyPair {
        val decoded = KeyCodec.publicKeyOf(ByteString(publicKey.encoded)).getOrNull()
        val public = requireNotNull(decoded) { "The public key is not one krypt reads" }
        public.handle = publicKey
        val encoded: ByteArray? = privateKey.encoded
        val parsed = encoded?.let { bytes -> parse(SecretBytes.adopt(bytes)) }
        val private = parsed?.withPublic(public)
            ?: PrivateKey.ofPlatform(publicKey = public, platformHandle = privateKey)
        private.handle = privateKey
        parsed?.destroy()
        return KeyPair(publicKey = public, privateKey = private)
    }
}
