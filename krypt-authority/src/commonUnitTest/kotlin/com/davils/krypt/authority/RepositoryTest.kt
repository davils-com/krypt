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

package com.davils.krypt.authority

import com.davils.kore.core.outcome.failureOrNull
import com.davils.krypt.authority.fixture.FlakyRepository
import com.davils.krypt.authority.fixture.MemoryRepository
import com.davils.krypt.authority.fixture.MovableClock
import com.davils.krypt.authority.fixture.NOW
import com.davils.krypt.authority.fixture.issued
import com.davils.krypt.authority.fixture.rootAuthority
import com.davils.krypt.authority.fixture.serverRequest
import com.davils.krypt.authority.fixture.testEnvironment
import com.davils.krypt.primitive.Crypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

private const val BASE_SECONDS: Int = 2
private const val DELTA_SECONDS: Int = 4
private const val OVERLAP_MINUTES: Int = 5

private suspend fun flaky(repository: FlakyRepository, on: Crypto): CertificateAuthority {
    val root = rootAuthority(on = on)
    return CertificateAuthority(
        crypto = on,
        certificate = root.authority.certificate,
        signer = root.authority.signer,
        repository = repository,
    )
}

class RepositoryTest : FunSpec({
    test("a revocation recorded after the base list was cut is in the next delta") {
        val clock = MovableClock(NOW)
        val on = Crypto(testEnvironment(clock = clock))
        val repository = FlakyRepository()
        val authority = flaky(repository, on)
        val leaf = authority.issued(serverRequest())
        repository.gate = CompletableDeferred()
        val revoking = launch(start = CoroutineStart.UNDISPATCHED) { authority.revoke(leaf.serialNumber) }
        clock.at = NOW + BASE_SECONDS.seconds
        val base = authority.revocationList()
        base.find(leaf.serialNumber) shouldBe null
        repository.gate.complete(Unit)
        revoking.join()
        clock.at = NOW + DELTA_SECONDS.seconds
        authority.deltaRevocationList(base).find(leaf.serialNumber) shouldNotBe null
        val tight = authority.deltaRevocationList(base = base, overlap = Duration.ZERO)
        tight.find(leaf.serialNumber) shouldBe null
        shouldThrow<IllegalArgumentException> { authority.deltaRevocationList(base = base, overlap = (-1).minutes) }
        shouldThrow<IllegalArgumentException> { authority.deltaRevocationList(base = base, validity = Duration.ZERO) }
        CertificateAuthority.DEFAULT_OVERLAP shouldBe OVERLAP_MINUTES.minutes
    }

    test("a failing repository yields a typed failure") {
        val on = Crypto(testEnvironment(clock = MovableClock(NOW)))
        val repository = FlakyRepository(MemoryRepository())
        val authority = flaky(repository, on)
        val leaf = authority.issued(serverRequest())
        repository.failing += FlakyRepository.RECORD
        authority.issue(serverRequest()).failureOrNull() shouldBe IssuanceFailure.RepositoryUnavailable
        repository.failing += FlakyRepository.FIND
        authority.revoke(leaf.serialNumber).failureOrNull() shouldBe RevocationFailure.RepositoryUnavailable
        repository.failing -= FlakyRepository.FIND
        repository.failing += FlakyRepository.REVOKE
        authority.revoke(leaf.serialNumber).failureOrNull() shouldBe RevocationFailure.RepositoryUnavailable
        repository.failing += FlakyRepository.LIST
        shouldThrow<IllegalStateException> { authority.revocationList() }
        repository.failing -= FlakyRepository.LIST
        repository.failing += FlakyRepository.NUMBER
        shouldThrow<IllegalStateException> { authority.revocationList() }
    }
})
