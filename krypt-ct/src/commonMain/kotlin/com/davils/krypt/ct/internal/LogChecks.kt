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

package com.davils.krypt.ct.internal

import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.ct.CtCompliance
import com.davils.krypt.ct.CtLog
import com.davils.krypt.ct.CtPolicy
import com.davils.krypt.ct.SctResult
import com.davils.krypt.ct.SctStatus
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.Certificate
import kotlin.time.Duration.Companion.days

internal object LogChecks {
    suspend fun permitted(crypto: Crypto, algorithm: SignatureAlgorithm?, key: PublicKey): SignatureAlgorithm? {
        val policy = crypto.environment.policy
        val isRsaPermitted = key.family != KeyFamily.Rsa || policy.permitsRsa(key.bits, AlgorithmUse.Verify)
        val isCurvePermitted = key.curve?.let { curve -> policy.permitsCurve(curve) } != false
        val isKeyPermitted = isRsaPermitted && isCurvePermitted
        val permitted = algorithm?.takeIf { found ->
            found.family == key.family && isKeyPermitted && policy.permits(found, AlgorithmUse.Verify)
        }
        return permitted?.takeIf { found -> crypto.capabilities.supports(found) }
    }

    fun required(certificate: Certificate, policy: CtPolicy): Int {
        val lifetime = certificate.notAfter - certificate.notBefore
        val isShort = lifetime <= policy.shortLifetimeDays.days
        return listOf(policy.minimumForLong, policy.minimumForShort)[isShort.compareTo(false)]
    }

    fun compliance(required: Int, logs: Int, operators: Int, policy: CtPolicy): CtCompliance {
        val shortfall = listOf(
            CtCompliance.NotEnoughTimestamps.takeIf { logs < required },
            CtCompliance.NotEnoughOperators.takeIf { operators < policy.minimumOperators },
        )
        return shortfall.firstNotNullOfOrNull { found -> found } ?: CtCompliance.Compliant
    }

    fun validLogs(results: List<SctResult>): List<CtLog> {
        val valid = results.filter { result -> result.status == SctStatus.Valid }
        val logs = valid.mapNotNull { result -> result.log }
        return logs.distinct()
    }
}
