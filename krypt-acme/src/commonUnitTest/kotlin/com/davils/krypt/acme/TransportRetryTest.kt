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

package com.davils.krypt.acme

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.acme.fixture.FlakyTransport
import com.davils.krypt.acme.fixture.crypto
import com.davils.krypt.acme.fixture.failure
import com.davils.krypt.testing.acme.FakeAcmeServer
import io.kotest.common.ExperimentalKotest
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

private fun clientOf(transport: FlakyTransport, server: FakeAcmeServer, retry: Boolean = true): AcmeClient {
    if (!retry) {
        return AcmeClient(
            transport = transport,
            directoryUrl = server.directoryUrl,
            crypto = crypto,
            limits = AcmeLimits.Default,
            transportRetry = null,
        )
    }
    return AcmeClient(transport = transport, directoryUrl = server.directoryUrl, crypto = crypto)
}

@OptIn(ExperimentalKotest::class)
class TransportRetryTest : FunSpec({
    coroutineTestScope = true

    test("tries a request whose transport threw again by the default retry") {
        val server = FakeAcmeServer(crypto = crypto)
        val transport = FlakyTransport(server, failures = 2)

        val directory = clientOf(transport, server).directory()

        directory.shouldBeInstanceOf<Outcome.Success<AcmeDirectory>>()

        transport.calls shouldBe AcmeClient.DEFAULT_TRANSPORT_RETRY.maxAttempts
    }

    test("gives up as a failed transport once the attempts are used up") {
        val server = FakeAcmeServer(crypto = crypto)
        val transport = FlakyTransport(server, failures = Int.MAX_VALUE)

        val directory = clientOf(transport, server).directory()

        directory.failure() shouldBe AcmeError.Transport

        transport.calls shouldBe AcmeClient.DEFAULT_TRANSPORT_RETRY.maxAttempts
    }

    test("tries each request once without a retry") {
        val server = FakeAcmeServer(crypto = crypto)
        val transport = FlakyTransport(server, failures = 1)

        val directory = clientOf(transport, server, retry = false).directory()

        directory.failure() shouldBe AcmeError.Transport

        transport.calls shouldBe 1
    }
})
