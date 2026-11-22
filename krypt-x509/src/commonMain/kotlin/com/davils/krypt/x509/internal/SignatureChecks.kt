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

import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.Verification
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString

internal object SignatureChecks {
    suspend fun verify(
        crypto: Crypto,
        algorithm: SignatureAlgorithm?,
        key: PublicKey,
        data: ByteString,
        signature: ByteString,
    ): Verification {
        val policy = crypto.environment.policy
        val isRsaPermitted = key.family != KeyFamily.Rsa ||
            policy.permitsRsa(key.bits, AlgorithmUse.Verify)
        val isCurvePermitted = key.curve?.let { curve -> policy.permitsCurve(curve) } != false
        val isKeyPermitted = isRsaPermitted && isCurvePermitted
        val permitted = algorithm?.takeIf { found ->
            found.family == key.family && isKeyPermitted && policy.permits(found, AlgorithmUse.Verify)
        }
        val supported = permitted?.takeIf { found ->
            crypto.capabilities.supports(
                found,
            )
        } ?: return Verification.Invalid
        return crypto.signatures.verify(key = key, data = data, signature = signature, algorithm = supported)
    }
}
