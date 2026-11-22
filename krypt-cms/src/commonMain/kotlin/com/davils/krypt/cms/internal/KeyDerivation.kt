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

@file:OptIn(DavilsInternal::class, LegacyCryptography::class)

package com.davils.krypt.cms.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.asn1.Der
import com.davils.krypt.cms.internal.Algorithms.writeKeyWrap
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.hash.LegacyDerivations
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.buildByteString

private const val BYTE_BITS: Int = 8
private const val COUNTER_BYTES: Int = 4
private const val ENTITY_INFO: Int = 0
private const val SUPPLEMENTARY_INFO: Int = 2
private const val KEM_UKM: Int = 0
private const val BYTE_MASK: Int = 0xFF

internal object KeyDerivation {
    private val HKDFS: Map<DigestAlgorithm, KdfAlgorithm> = mapOf(
        DigestAlgorithm.Sha256 to KdfAlgorithm.HkdfSha256,
        DigestAlgorithm.Sha384 to KdfAlgorithm.HkdfSha384,
        DigestAlgorithm.Sha512 to KdfAlgorithm.HkdfSha512,
    )

    private val PBKDF2S: Map<DigestAlgorithm, KdfAlgorithm> = mapOf(
        DigestAlgorithm.Sha256 to KdfAlgorithm.Pbkdf2Sha256,
        DigestAlgorithm.Sha512 to KdfAlgorithm.Pbkdf2Sha512,
    )

    fun sharedInfo(wrap: KeyWrapAlgorithm, userKeyingMaterial: ByteString?): ByteString = Der.encode {
        sequence {
            writeKeyWrap(wrap)
            userKeyingMaterial?.let { ukm -> explicit(ENTITY_INFO) { octetString(ukm) } }
            explicit(SUPPLEMENTARY_INFO) { octetString(bigEndian(wrap.keyBytes * BYTE_BITS)) }
        }
    }

    fun kemInfo(wrap: KeyWrapAlgorithm, kekLength: Int, userKeyingMaterial: ByteString?): ByteString = Der.encode {
        sequence {
            writeKeyWrap(wrap)
            integer(kekLength.toLong())
            userKeyingMaterial?.let { ukm -> explicit(KEM_UKM) { octetString(ukm) } }
        }
    }

    suspend fun agreementKek(
        crypto: Crypto,
        secret: SecretBytes,
        scheme: ParsedRecipient.AgreementScheme,
        wrap: KeyWrapAlgorithm,
        userKeyingMaterial: ByteString?,
    ): SecretBytes {
        val info = sharedInfo(wrap, userKeyingMaterial)
        return when (scheme.isHkdf) {
            true -> crypto.derivations.hkdf(
                inputKey = secret,
                salt = userKeyingMaterial ?: ByteString(),
                info = info,
                length = wrap.keyBytes,
                algorithm = HKDFS.getValue(scheme.digest),
            )

            false -> x963(crypto = crypto, secret = secret, digest = scheme.digest, info = info, length = wrap.keyBytes)
        }
    }

    suspend fun x963(
        crypto: Crypto,
        secret: SecretBytes,
        digest: DigestAlgorithm,
        info: ByteString,
        length: Int,
    ): SecretBytes {
        val count = (length + digest.outputBytes - 1) / digest.outputBytes
        val blocks = List(count) { index ->
            val input = secret.reveal { bytes ->
                buildByteString {
                    append(bytes)
                    append(bigEndian(index + 1).toByteArray())
                    append(info.toByteArray())
                }
            }
            crypto.digests.digest(data = input, algorithm = digest)
        }
        return SecretBytes.copyOf(concat(blocks).substring(startIndex = 0, endIndex = length))
    }

    suspend fun passwordKek(
        crypto: Crypto,
        password: SecretText,
        derivation: ParsedRecipient.PasswordDerivation,
        length: Int,
    ): SecretBytes {
        val modern = PBKDF2S[derivation.prf] ?: return LegacyDerivations.pbkdf2Sha1(
            crypto = crypto,
            password = password,
            salt = derivation.salt,
            iterations = derivation.iterations,
            length = length,
        )
        return crypto.derivations.pbkdf2(
            password = password,
            salt = derivation.salt,
            iterations = derivation.iterations,
            length = length,
            algorithm = modern,
            use = AlgorithmUse.Verify,
        )
    }

    private fun bigEndian(value: Int): ByteString = ByteString(
        ByteArray(COUNTER_BYTES) { index ->
            (value ushr BYTE_BITS * (COUNTER_BYTES - 1 - index) and BYTE_MASK).toByte()
        },
    )
}
