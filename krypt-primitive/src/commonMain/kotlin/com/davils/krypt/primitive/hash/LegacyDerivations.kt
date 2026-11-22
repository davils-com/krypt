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

package com.davils.krypt.primitive.hash

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.internal.requireWellFormed
import com.davils.krypt.primitive.PolicyViolationException
import kotlinx.io.bytestring.ByteString

private const val MINIMUM_SALT: Int = 8
private const val MINIMUM_LENGTH: Int = 16
private const val MAXIMUM_LENGTH: Int = 1_024

/**
 * Password derivations that only reading old data needs, such as PBKDF2 with HMAC-SHA-1, the default pseudorandom
 * function of PBKDF2 that OpenSSL still writes into the password recipients of CMS.
 *
 * @since 1.0.0
 */
@DavilsInternal
public object LegacyDerivations {
    /**
     * Derives [length] bytes from [password] with PBKDF2 and HMAC-SHA-1, for verification only.
     *
     * The policy must accept SHA-1 for verification and [iterations] as verified iterations.
     *
     * @param crypto the primitives and their policy.
     * @param password the password, without an unpaired UTF-16 surrogate.
     * @param salt the salt, at least 8 bytes.
     * @param iterations the iteration count.
     * @param length the size of the derived key, 16 to 1024 bytes.
     * @return the derived key.
     * @throws IllegalArgumentException if the salt or the length is out of range or [password] holds an unpaired
     *   surrogate.
     * @throws PolicyViolationException if the policy refuses SHA-1 or the iteration count.
     * @since 1.0.0
     */
    @LegacyCryptography
    public suspend fun pbkdf2Sha1(
        crypto: Crypto,
        password: SecretText,
        salt: ByteString,
        iterations: Int,
        length: Int,
    ): SecretBytes {
        require(salt.size >= MINIMUM_SALT) { "A PBKDF2 salt has at least $MINIMUM_SALT bytes" }
        require(length in MINIMUM_LENGTH..MAXIMUM_LENGTH) { "PBKDF2 derives $MINIMUM_LENGTH to $MAXIMUM_LENGTH bytes" }
        requireWellFormed(password)
        crypto.permit(DigestAlgorithm.Sha1, AlgorithmUse.Verify)
        val policy = crypto.environment.policy
        if (!policy.permitsIterations(iterations, AlgorithmUse.Verify)) {
            throw PolicyViolationException("$iterations iterations")
        }
        val derived = crypto.backend.pbkdf2(
            digest = DigestAlgorithm.Sha1,
            password = password,
            salt = salt.toByteArray(),
            iterations = iterations,
            length = length,
        )
        return SecretBytes.adopt(derived)
    }
}
