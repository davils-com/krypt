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

package com.davils.krypt.cose.internal

import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseAlgorithmKind
import com.davils.krypt.cose.CoseFailure
import com.davils.krypt.cose.CoseHeaders
import com.davils.krypt.cose.internal.CoseException.Companion.ensure
import com.davils.krypt.cose.key.CoseCurve
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PublicKey

internal class Permissions(private val crypto: Crypto) {
    suspend fun check(algorithm: CoseAlgorithm, use: AlgorithmUse) {
        ensure(isAllowed(algorithm, use), CoseFailure.AlgorithmNotPermitted)
    }

    suspend fun isPermitted(algorithm: Algorithm, use: AlgorithmUse): Boolean =
        crypto.environment.policy.permits(algorithm, use) && crypto.capabilities.supports(algorithm)

    suspend fun isAllowed(algorithm: CoseAlgorithm, use: AlgorithmUse): Boolean {
        val parts = listOfNotNull(algorithm.signature, algorithm.mac, algorithm.aead, algorithm.keyWrap, algorithm.kdf)
        return parts.all { part -> isPermitted(part, use) }
    }

    suspend fun distributionOf(
        protectedHeaders: CoseHeaders,
        unprotectedHeaders: CoseHeaders,
        allowed: Set<CoseAlgorithm>,
    ): CoseAlgorithm? {
        val protectedItem = protectedHeaders[HeaderLabels.ALGORITHM]
        val item = protectedItem ?: unprotectedHeaders[HeaderLabels.ALGORITHM]
        val algorithm = item?.longOrNull()?.let { id -> CoseAlgorithm.of(id) }
        ensure(protectedItem != null || algorithm?.kdf == null, CoseFailure.Malformed)
        val candidate = algorithm?.takeIf { found ->
            found in allowed && found.kind == CoseAlgorithmKind.KeyDistribution
        }
        val isAllowed = candidate?.let { found -> isAllowed(found, AlgorithmUse.Verify) } == true
        return candidate?.takeIf { isAllowed }
    }

    fun isKeyPermitted(key: PublicKey, use: AlgorithmUse): Boolean {
        val policy = crypto.environment.policy
        val isRsaPermitted = key.family != KeyFamily.Rsa || policy.permitsRsa(key.bits, use)
        val isCurvePermitted = key.curve?.let { curve -> policy.permitsCurve(curve) } != false
        return isRsaPermitted && isCurvePermitted
    }

    companion object {
        private val KEY_WRAP_IDS: Map<KeyWrapAlgorithm?, Long> = mapOf(
            KeyWrapAlgorithm.Aes128Kw to CoseAlgorithm.A128Kw.id,
            KeyWrapAlgorithm.Aes192Kw to CoseAlgorithm.A192Kw.id,
            KeyWrapAlgorithm.Aes256Kw to CoseAlgorithm.A256Kw.id,
        )
        private val CONTENT_KEY_BYTES: Map<CoseAlgorithm, Int> = CoseAlgorithm.entries.associateWith { algorithm ->
            val digest = algorithm.mac?.digest
            listOfNotNull(algorithm.aead?.keyBytes, digest?.outputBytes).sum()
        }

        fun contentKeyBytes(algorithm: CoseAlgorithm): Int = CONTENT_KEY_BYTES.getValue(algorithm)

        fun derivedKeyBytes(algorithm: CoseAlgorithm, content: CoseAlgorithm): Int =
            algorithm.keyWrap?.keyBytes ?: contentKeyBytes(content)

        fun kdfAlgorithmId(algorithm: CoseAlgorithm, content: CoseAlgorithm): Long =
            KEY_WRAP_IDS[algorithm.keyWrap] ?: content.id

        fun signatureOf(algorithm: CoseAlgorithm, curve: CoseCurve?): SignatureAlgorithm {
            val edwards = SignatureAlgorithm.Ed448.takeIf { curve == CoseCurve.Ed448 } ?: SignatureAlgorithm.Ed25519
            return algorithm.signature ?: edwards
        }
    }
}
