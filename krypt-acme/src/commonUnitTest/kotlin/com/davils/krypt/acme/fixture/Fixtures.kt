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

package com.davils.krypt.acme.fixture

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.kore.testing.TestClock
import com.davils.krypt.acme.AcmeClient
import com.davils.krypt.acme.AcmeFailure
import com.davils.krypt.acme.AcmeLimits
import com.davils.krypt.acme.AcmeProblem
import com.davils.krypt.acme.AcmeProblemType
import com.davils.krypt.acme.AcmeTransport
import com.davils.krypt.acme.account.AccountKey
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.testing.acme.FakeAcmeServer
import com.davils.krypt.testing.testCrypto
import kotlin.time.Instant

internal val NOW: Instant = Instant.fromEpochSeconds(1_800_000_000L)

internal val clock: TestClock = TestClock(NOW)

internal val crypto: Crypto = testCrypto(clock = clock)

internal suspend fun accountKey(type: KeyType = KeyType.P256): AccountKey =
    AccountKey(crypto.keys.generate(type).privateKey)

internal suspend fun signer(): Signer = crypto.signatures.signer(crypto.keys.generate(KeyType.P256).privateKey)

internal fun clientOf(server: FakeAcmeServer, limits: AcmeLimits = AcmeLimits.Default): AcmeClient =
    AcmeClient(transport = server, directoryUrl = server.directoryUrl, crypto = crypto, limits = limits)

internal fun clientOf(transport: AcmeTransport, limits: AcmeLimits = AcmeLimits.Default): AcmeClient =
    AcmeClient(transport = transport, directoryUrl = DIRECTORY_URL, crypto = crypto, limits = limits)

internal fun <T> Outcome<T, AcmeFailure>.value(): T = checkNotNull(getOrNull()) { "Expected a success: $this" }

internal fun Outcome<*, AcmeFailure>.failure(): AcmeFailure? = failureOrNull()

internal fun Outcome<*, AcmeFailure>.problem(): AcmeProblemType? = (failureOrNull() as? AcmeProblem)?.kind
