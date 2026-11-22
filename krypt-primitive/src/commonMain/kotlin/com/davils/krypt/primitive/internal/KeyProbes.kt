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

import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

internal object KeyProbes {
    private val PROBE: ByteString = "krypt key pair probe".encodeToByteString()

    suspend fun matches(crypto: Crypto, privateKey: PrivateKey, publicKey: PublicKey): Boolean =
        when (publicKey.family) {
            KeyFamily.Ed25519 -> signs(crypto, privateKey, publicKey)
            KeyFamily.Ed448 -> signs(crypto, privateKey, publicKey)
            KeyFamily.Ec -> signs(crypto, privateKey, publicKey)
            KeyFamily.Rsa -> signs(crypto, privateKey, publicKey)
            KeyFamily.MlDsa -> signs(crypto, privateKey, publicKey)
            KeyFamily.X25519 -> agrees(crypto, privateKey, publicKey)
            KeyFamily.X448 -> agrees(crypto, privateKey, publicKey)
            KeyFamily.MlKem -> encapsulates(crypto, privateKey, publicKey)
        }

    private suspend fun signs(crypto: Crypto, privateKey: PrivateKey, publicKey: PublicKey): Boolean {
        val signature = crypto.signatures.sign(key = privateKey, data = PROBE)
        return crypto.signatures.verify(key = publicKey, data = PROBE, signature = signature).isValid
    }

    private suspend fun agrees(crypto: Crypto, privateKey: PrivateKey, publicKey: PublicKey): Boolean {
        val type = KeyType.entries.first { candidate -> candidate.family == publicKey.family }
        val ephemeral = crypto.keys.generate(type)
        val mine = crypto.agreements.agree(privateKey, ephemeral.publicKey)
        val theirs = crypto.agreements.agree(ephemeral.privateKey, publicKey)
        ephemeral.privateKey.destroy()
        val isEqual = mine == theirs
        mine.destroy()
        theirs.destroy()
        return isEqual
    }

    private suspend fun encapsulates(crypto: Crypto, privateKey: PrivateKey, publicKey: PublicKey): Boolean {
        val algorithm = crypto.kems.defaultFor(publicKey)
        val encapsulation = crypto.kems.encapsulate(recipient = publicKey, algorithm = algorithm)
        val opened = crypto.kems.decapsulate(
            recipient = privateKey,
            encapsulated = encapsulation.encapsulated,
            algorithm = algorithm,
        )
        val isEqual = opened == encapsulation.sharedSecret
        opened?.destroy()
        encapsulation.sharedSecret.destroy()
        return isEqual
    }
}
