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

package com.davils.krypt.stream

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.TimeSource

private const val CORE: Int = 50
private const val ENTRY_START: Int = CORE + 1
private const val ITERATION_OFFSET: Int = 1 + 2 + 16
private const val WRAPPED_LENGTH_OFFSET: Int = 1 + 2 + 20
private const val HOSTILE_ITERATIONS: Int = 1_000_000
private const val ENTRIES: Int = 16

private val cheap: Crypto = Crypto(
    environment {
        policy = cryptoPolicy {
            minimumIterations = 1_000
            minimumVerifiedIterations = 1_000
        }
    },
)

private fun u16(bytes: ByteArray, offset: Int): Int =
    ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

private fun hostile(container: ByteString, entries: Int): ByteString {
    val bytes = container.toByteArray()
    val wrapped = u16(bytes, ENTRY_START + WRAPPED_LENGTH_OFFSET)
    val entryEnd = ENTRY_START + WRAPPED_LENGTH_OFFSET + 2 + wrapped
    val entry = bytes.copyOfRange(ENTRY_START, entryEnd)
    val at = ITERATION_OFFSET
    entry[at] = (HOSTILE_ITERATIONS ushr 24).toByte()
    entry[at + 1] = (HOSTILE_ITERATIONS ushr 16).toByte()
    entry[at + 2] = (HOSTILE_ITERATIONS ushr 8).toByte()
    entry[at + 3] = HOSTILE_ITERATIONS.toByte()
    val out = bytes.copyOfRange(0, CORE).toMutableList()
    out += entries.toByte()
    repeat(entries) { out += entry.toList() }
    out += bytes.copyOfRange(entryEnd, bytes.size).toList()
    return ByteString(out.toByteArray())
}

class AuditStreamTest : FunSpec({
    test("a hostile container cannot multiply the PBKDF2 work of a password credential by its recipients") {
        val containers = Containers(cheap)
        val container = containers.encrypt(
            plaintext = ByteString(ByteArray(10)),
            recipients = listOf(Recipient.Password(SecretText.of("right"), iterations = 1_000)),
        )
        val wrong = listOf(Credential.Password(SecretText.of("wrong")))
        val one = hostile(container, 1)
        val many = hostile(container, ENTRIES)
        containers.decrypt(one, wrong)
        val clock = TimeSource.Monotonic
        val startOne = clock.markNow()
        containers.decrypt(one, wrong) shouldBe Outcome.Failure(StreamFailure.NotARecipient)
        val single = startOne.elapsedNow().inWholeMilliseconds
        val startMany = clock.markNow()
        containers.decrypt(many, wrong) shouldBe Outcome.Failure(StreamFailure.NotARecipient)
        val multiplied = startMany.elapsedNow().inWholeMilliseconds
        println("AUDIT B password DoS: 1 entry ${single} ms, $ENTRIES entries ${multiplied} ms")
        multiplied shouldBeLessThan single * 3 + 100
    }
})
