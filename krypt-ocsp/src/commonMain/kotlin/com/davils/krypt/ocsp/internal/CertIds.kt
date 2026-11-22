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

package com.davils.krypt.ocsp.internal

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.ocsp.CertId
import com.davils.krypt.ocsp.OcspIssuer
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

internal object CertIds {
    suspend fun of(crypto: Crypto, issuer: OcspIssuer, serialNumber: DerInteger, algorithm: DigestAlgorithm): CertId {
        require(algorithm in OcspOids.DIGESTS) { "OCSP identifies certificates with SHA-1 or SHA-2 only" }
        val digests = crypto.digests
        val key = keyOf(issuer.publicKey.encoded)
        return CertId(
            hashAlgorithm = algorithm,
            issuerNameHash = digests.digest(
                data = issuer.name.encoded,
                algorithm = algorithm,
                use = AlgorithmUse.Verify,
            ),
            issuerKeyHash = digests.digest(data = key, algorithm = algorithm, use = AlgorithmUse.Verify),
            serialNumber = serialNumber,
        )
    }

    fun isPermitted(crypto: Crypto, algorithm: DigestAlgorithm): Boolean {
        val policy = crypto.environment.policy
        return policy.permits(algorithm, AlgorithmUse.Verify)
    }

    private fun keyOf(subjectPublicKeyInfo: ByteString): ByteString {
        val key = Der.decodeOrNull(subjectPublicKeyInfo) {
            readSequence {
                readElement(Tag.Sequence)
                readBitString().bytes
            }
        }
        return key ?: subjectPublicKeyInfo
    }
}
