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

package com.davils.krypt.testing

import com.davils.kore.testing.TestClock
import com.davils.krypt.core.audit.AuditAction
import com.davils.krypt.core.audit.AuditEntry
import com.davils.krypt.core.audit.AuditOutcome
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.primitive.Crypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Instant

private const val SEED: Long = 9L
private const val KEY_LENGTH: Int = 32
private const val SUBJECT: String = "key-1"

private fun entry(action: AuditAction): AuditEntry = AuditEntry(
    action = action,
    subject = SUBJECT,
    outcome = AuditOutcome.Succeeded,
    at = Instant.fromEpochMilliseconds(0L),
)

private fun secretOf(crypto: Crypto): List<Byte> {
    val key = crypto.keys.generateSecret()
    return key.export().reveal { bytes -> bytes.toList() }
}

class TestEnvironmentsTest : FunSpec({
    test("an audit log keeps its entries or refuses them") {
        val rotate = AuditAction("key.rotate")
        val destroy = AuditAction("key.destroy")
        val log = AuditLog()
        log.record(entry(rotate))
        log.record(entry(destroy))
        log.entries shouldBe listOf(entry(rotate), entry(destroy))
        log.of(rotate) shouldBe listOf(entry(rotate))
        log.toString() shouldBe "AuditLog(2 entries)"
        val failing = AuditLog(isFailing = true)
        shouldThrow<IllegalStateException> { failing.record(entry(rotate)) }
        failing.entries shouldBe emptyList()
    }

    test("a test environment follows the given clock, seed and changes") {
        val clock = TestClock()
        val environment = testEnvironment(clock = clock, seed = SEED) { policy = CryptoPolicy.Cnsa2 }
        environment.clock shouldBe clock
        environment.policy shouldBe CryptoPolicy.Cnsa2
        environment.random.shouldBeInstanceOf<SeededRandom>().seed shouldBe SEED
        testEnvironment().policy shouldBe CryptoPolicy.Modern
        val first = secretOf(testCrypto())
        val second = secretOf(testCrypto())
        first shouldBe second
        first.size shouldBe KEY_LENGTH
    }
})
