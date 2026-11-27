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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.keyset.internal

import com.davils.kontinuity.core.backoff.exponential
import com.davils.kontinuity.core.backoff.jittered
import com.davils.kontinuity.core.backoff.proportional
import com.davils.kontinuity.retry.Retry
import com.davils.kontinuity.retry.retry
import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.Environment
import com.davils.krypt.core.telemetry.resilience
import com.davils.krypt.keyset.KeysetFailure
import kotlin.time.Duration.Companion.milliseconds

private const val RETRY_NAME: String = "krypt-keyset-update"

internal object ConflictRetries {
    fun of(attempts: Int, source: Environment): Retry = retry(name = RETRY_NAME, environment = source.resilience()) {
        maxAttempts = attempts
        val growing = exponential(initial = 10.milliseconds, maximum = 500.milliseconds)
        backoff = growing.jittered(proportional())
        failures { ignore<Throwable>() }
        results { failIf<Outcome<*, *>> { result -> result == Outcome.Failure(KeysetFailure.Conflict) } }
    }
}
