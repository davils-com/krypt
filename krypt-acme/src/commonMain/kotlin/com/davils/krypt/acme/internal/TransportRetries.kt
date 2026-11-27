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

package com.davils.krypt.acme.internal

import com.davils.kontinuity.core.backoff.exponential
import com.davils.kontinuity.core.backoff.jittered
import com.davils.kontinuity.core.backoff.proportional
import com.davils.kontinuity.retry.Retry
import com.davils.kontinuity.retry.RetryConfig
import com.davils.kontinuity.retry.retry
import com.davils.kontinuity.retry.retryConfig
import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.telemetry.resilience
import com.davils.krypt.primitive.Crypto
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

private const val RETRY_NAME: String = "krypt-acme-transport"
private const val ATTEMPTS: Int = 3

internal object TransportRetries {
    val DEFAULT: RetryConfig = retryConfig {
        maxAttempts = ATTEMPTS
        val growing = exponential(initial = 200.milliseconds, maximum = 2.seconds)
        backoff = growing.jittered(proportional())
    }

    fun of(config: RetryConfig, crypto: Crypto): Retry {
        val source = crypto.environment
        return retry(name = RETRY_NAME, config = config, environment = source.resilience())
    }
}
