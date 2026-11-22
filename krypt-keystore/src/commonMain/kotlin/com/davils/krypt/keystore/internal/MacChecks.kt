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

package com.davils.krypt.keystore.internal

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.keystore.KeystoreFailure
import com.davils.krypt.keystore.KeystoreLimits
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

private const val MINIMUM_SALT: Int = 16

internal class MacChecks(
    private val crypto: Crypto,
    private val password: SecretText,
    private val budget: PasswordBudget,
) {
    suspend fun check(mac: MacParts, data: ByteString, limits: KeystoreLimits) {
        when (mac) {
            is MacParts.Classic -> classic(mac = mac, data = data, limits = limits)
            is MacParts.Pbmac1 -> pbmac1(mac = mac, data = data)
        }
    }

    private suspend fun classic(mac: MacParts.Classic, data: ByteString, limits: KeystoreLimits) {
        val digest = KeystoreRefusal.present(mac.digest, KeystoreFailure.Unsupported)
        KeystoreRefusal.ensure(mac.iterations <= limits.maximumMacIterations, KeystoreFailure.Refused)
        budget.spend(mac.iterations)
        val key = Pkcs12Kdf.macKey(
            crypto = crypto,
            digest = digest,
            password = password,
            salt = mac.salt,
            iterations = mac.iterations,
        )
        verify(key = key, data = data, mac = mac, algorithm = Pkcs12Oids.HMAC_OF_DIGEST.getValue(digest))
    }

    private suspend fun pbmac1(mac: MacParts.Pbmac1, data: ByteString) {
        val digest = KeystoreRefusal.present(mac.kdf, KeystoreFailure.Unsupported)
        val kdf = KeystoreRefusal.present(Pkcs12Oids.PBKDF2S[digest], KeystoreFailure.Unsupported)
        val algorithm = KeystoreRefusal.present(mac.mac, KeystoreFailure.Unsupported)
        KeystoreRefusal.ensure(mac.salt.size >= MINIMUM_SALT, KeystoreFailure.Unsupported)
        KeystoreRefusal.ensure(mac.keyBytes >= SecretKey.MINIMUM_BYTES, KeystoreFailure.Refused)
        val isPermitted = crypto.environment.policy.permitsIterations(mac.iterations, AlgorithmUse.Verify)
        KeystoreRefusal.ensure(isPermitted, KeystoreFailure.Refused)
        budget.spend(mac.iterations)
        val key = crypto.derivations.pbkdf2(
            password = password,
            salt = mac.salt,
            iterations = mac.iterations,
            length = mac.keyBytes,
            algorithm = kdf,
            use = AlgorithmUse.Verify,
        )
        verify(key = key, data = data, mac = mac, algorithm = algorithm)
    }

    private suspend fun verify(key: SecretBytes, data: ByteString, mac: MacParts, algorithm: MacAlgorithm) {
        val secret = key.use { bytes -> SecretKey.of(bytes) }
        val verification = try {
            crypto.macs.verify(key = secret, data = data, tag = mac.tag, algorithm = algorithm)
        } finally {
            secret.destroy()
        }
        KeystoreRefusal.ensure(verification.isValid, KeystoreFailure.WrongPassword)
    }
}
