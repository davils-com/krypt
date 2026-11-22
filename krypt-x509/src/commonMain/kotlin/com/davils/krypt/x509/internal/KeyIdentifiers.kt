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

package com.davils.krypt.x509.internal

import com.davils.krypt.asn1.Der
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

private const val IDENTIFIER_BYTES: Int = 20

internal object KeyIdentifiers {
    suspend fun of(crypto: Crypto, subjectPublicKeyInfo: ByteString): ByteString {
        val key = checkNotNull(
            Der.decodeOrNull(subjectPublicKeyInfo) {
                readSequence {
                    readElement()
                    readBitString()
                }
            },
        )
        val digest = crypto.digests.digest(key.bytes, DigestAlgorithm.Sha256)
        return digest.substring(startIndex = 0, endIndex = IDENTIFIER_BYTES)
    }
}
