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

package com.davils.krypt.keyset.internal

import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.keyset.KeyId
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.KeyStatus
import com.davils.krypt.keyset.KeysetKey
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import kotlin.time.Instant

internal object KeyFactory {
    suspend fun generate(crypto: Crypto, purpose: KeyPurpose): KeysetKey = when (purpose) {
        is KeyPurpose.Aead -> symmetric(crypto = crypto, algorithm = purpose.algorithm, size = purpose.secretBytes)
        is KeyPurpose.Mac -> symmetric(crypto = crypto, algorithm = purpose.algorithm, size = purpose.secretBytes)
        is KeyPurpose.Signing -> asymmetric(crypto, purpose.type)
        is KeyPurpose.Hybrid -> asymmetric(crypto, purpose.keyType)
    }

    private fun symmetric(crypto: Crypto, algorithm: Algorithm, size: Int): KeysetKey {
        val isPermitted = crypto.environment.policy.permits(algorithm, AlgorithmUse.Protect)
        if (!isPermitted) throw PolicyViolationException("${algorithm.algorithmName} (${AlgorithmUse.Protect})")
        return KeysetKey(
            id = KeyId.random(crypto.environment.random),
            status = KeyStatus.Enabled,
            createdAt = now(crypto),
            secret = crypto.keys.generateSecret(size),
            privateKey = null,
            publicKey = null,
        )
    }

    private fun now(crypto: Crypto): Instant {
        val now = crypto.environment.clock.now()
        return Instant.fromEpochMilliseconds(now.toEpochMilliseconds())
    }

    private suspend fun asymmetric(crypto: Crypto, type: KeyType): KeysetKey {
        val pair = crypto.keys.generate(type)
        return KeysetKey(
            id = KeyId.random(crypto.environment.random),
            status = KeyStatus.Enabled,
            createdAt = now(crypto),
            secret = null,
            privateKey = pair.privateKey,
            publicKey = pair.publicKey,
        )
    }
}
