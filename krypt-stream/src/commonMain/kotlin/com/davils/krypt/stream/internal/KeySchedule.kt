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

package com.davils.krypt.stream.internal

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.stream.StreamSuite
import kotlinx.io.bytestring.ByteString

private const val COMMITMENT_LABEL: String = "KRYPT/1 commitment"
private const val HEADER_LABEL: String = "KRYPT/1 header"
private const val PAYLOAD_LABEL: String = "KRYPT/1 payload"
private const val MAC_KEY_BYTES: Int = 32

internal class KeySchedule(val payload: SecretKey, val commitment: ByteString, val macKey: SecretKey) {
    fun destroy() {
        payload.destroy()
        macKey.destroy()
    }

    companion object {
        const val DATA_KEY_BYTES: Int = 32
        val RECIPIENT_LABEL: ByteString = Octets.utf8("KRYPT/1 recipient ")

        suspend fun context(crypto: Crypto, core: ByteString, associatedData: ByteString): ByteString {
            val coreDigest = crypto.digests.digest(core, DigestAlgorithm.Sha256)
            val dataDigest = crypto.digests.digest(associatedData, DigestAlgorithm.Sha256)
            return Octets.concat(coreDigest, dataDigest)
        }

        suspend fun derive(
            crypto: Crypto,
            dataKey: SecretBytes,
            salt: ByteString,
            context: ByteString,
            suite: StreamSuite,
        ): KeySchedule {
            suspend fun expand(label: String, length: Int): SecretBytes = crypto.derivations.hkdf(
                inputKey = dataKey,
                salt = salt,
                info = Octets.concat(Octets.utf8(label), context),
                length = length,
            )
            val commitment = expand(COMMITMENT_LABEL, HeaderCodec.COMMITMENT_BYTES).use { secret ->
                secret.reveal { bytes -> ByteString(bytes) }
            }
            return KeySchedule(
                payload = SecretKey.of(expand(PAYLOAD_LABEL, suite.aead.keyBytes)),
                commitment = commitment,
                macKey = SecretKey.of(expand(HEADER_LABEL, MAC_KEY_BYTES)),
            )
        }
    }
}
