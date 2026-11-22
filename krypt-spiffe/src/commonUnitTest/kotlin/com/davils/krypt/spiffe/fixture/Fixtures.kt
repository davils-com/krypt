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

package com.davils.krypt.spiffe.fixture

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.spiffe.bundle.TrustBundles
import com.davils.krypt.x509.Certificates
import kotlin.time.Instant

internal const val DOMAIN: String = "example.org"
internal const val FOREIGN: String = "example.com"
internal const val WORKLOAD: String = "spiffe://example.org/ns/prod/sa/api"
internal const val FOREIGN_WORKLOAD: String = "spiffe://example.com/ns/prod/sa/api"
internal const val DOMAIN_ID: String = "spiffe://example.org"
internal const val FOREIGN_DOMAIN_ID: String = "spiffe://example.com"
internal const val DAYS: Int = 30

internal val NOW: Instant = Instant.fromEpochSeconds(1_800_000_000L)

internal val crypto: Crypto = Crypto(environment { clock = FixedClock })

internal val compatible: Crypto = Crypto(
    environment {
        clock = FixedClock
        policy = CryptoPolicy.Compatible
    },
)

internal val certificates: Certificates = Certificates(crypto)

internal val codec: TrustBundles = TrustBundles(crypto)

internal val domain: TrustDomain = TrustDomain.of(DOMAIN)

internal val foreign: TrustDomain = TrustDomain.of(FOREIGN)

internal val workload: SpiffeId = SpiffeId.parse(WORKLOAD).value()

internal fun <T, F> Outcome<T, F>.value(): T = checkNotNull(getOrNull()) { "Expected a success: $this" }

internal fun <T, F> Outcome<T, F>.failure(): F? = failureOrNull()
