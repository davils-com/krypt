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

import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readRemaining
import kotlinx.io.bytestring.ByteString

private const val EC_VERSION: Int = 1

internal object PemKeys {
    const val PRIVATE_KEY: String = "PRIVATE KEY"
    const val ENCRYPTED_PRIVATE_KEY: String = "ENCRYPTED PRIVATE KEY"
    const val RSA_PRIVATE_KEY: String = "RSA PRIVATE KEY"
    const val EC_PRIVATE_KEY: String = "EC PRIVATE KEY"
    const val PUBLIC_KEY: String = "PUBLIC KEY"
    const val RSA_PUBLIC_KEY: String = "RSA PUBLIC KEY"

    fun pkcs8OfPkcs1(rsaPrivateKey: ByteString): ByteString =
        KeyCodec.pkcs8Of(algorithm = KeyCodec.rsaAlgorithm(), privateKey = rsaPrivateKey)

    fun pkcs8OfSec1(ecPrivateKey: ByteString): ByteString? {
        val curve = Der.decodeOrNull(ecPrivateKey) {
            readSequence {
                readInt(EC_VERSION..EC_VERSION)
                readOctetString()
                val oid = readOptionalExplicit(0) { readObjectIdentifier() }
                readRemaining()
                oid
            }
        }
        val known = curve?.let { oid -> KeyCodec.curveOf(oid) }
        return known?.let { found ->
            KeyCodec.pkcs8Of(
                algorithm = KeyCodec.ecAlgorithm(found),
                privateKey = ecPrivateKey,
            )
        }
    }

    fun spkiOfPkcs1(rsaPublicKey: ByteString): ByteString = KeyCodec.spkiOf(
        algorithm = KeyCodec.rsaAlgorithm(),
        publicBits = BitString(rsaPublicKey),
    )

    fun isLegacyEncrypted(headers: List<Pair<String, String>>): Boolean =
        headers.any { (name, value) -> name.equals("Proc-Type", ignoreCase = true) && value.contains("ENCRYPTED") }
}
