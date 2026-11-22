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

package com.davils.krypt.core.audit

import com.davils.kore.testing.HostileFragments
import com.davils.kore.testing.isSafeToShow
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlin.time.Instant

private const val ROTATED: String = "keyset.key.rotated"
private const val SUBJECT: String = "serial:01"
private const val TOO_LONG: Int = 65
private const val TOO_MANY: Int = 33
private val ISSUED: AuditAction = AuditAction("ca.issued")
private val AT: Instant = Instant.fromEpochSeconds(1)

private fun entry(
    action: AuditAction = ISSUED,
    subject: String = SUBJECT,
    outcome: AuditOutcome = AuditOutcome.Succeeded,
    attributes: Map<String, String> = emptyMap(),
): AuditEntry = AuditEntry(action = action, subject = subject, outcome = outcome, at = AT, attributes = attributes)

class AuditTest : FunSpec({
    test("an action name is checked and compared by its value") {
        val action = AuditAction(ROTATED)
        action shouldBe AuditAction(ROTATED)
        action shouldNotBe AuditAction("keyset.key-destroyed")
        action.equals(ROTATED) shouldBe false
        action.hashCode() shouldBe ROTATED.hashCode()
        action.toString() shouldBe ROTATED
        (action < AuditAction("z")) shouldBe true
        AuditAction("a.b-c9").value shouldBe "a.b-c9"
        shouldThrow<IllegalArgumentException> { AuditAction("") }
        shouldThrow<IllegalArgumentException> { AuditAction("Key") }
        shouldThrow<IllegalArgumentException> { AuditAction("a".repeat(TOO_LONG)) }
        shouldThrow<IllegalArgumentException> { AuditAction("key_rotated") }
    }

    test("an entry sorts its attributes and compares every property") {
        val sorted = entry(attributes = mapOf("z" to "1", "a" to "2"))
        sorted.attributes.keys.toList() shouldBe listOf("a", "z")
        sorted shouldBe entry(attributes = mapOf("a" to "2", "z" to "1"))
        sorted.hashCode() shouldBe entry(attributes = mapOf("a" to "2", "z" to "1")).hashCode()
        entry() shouldNotBe entry(subject = "serial:02")
        entry() shouldNotBe entry(action = AuditAction("ca.revoked"))
        entry() shouldNotBe entry(outcome = AuditOutcome.Refused)
        entry() shouldNotBe entry(attributes = mapOf("a" to "1"))
        entry().equals(SUBJECT) shouldBe false
        val later = AuditEntry(
            action = ISSUED,
            subject = SUBJECT,
            outcome = AuditOutcome.Succeeded,
            at = Instant.DISTANT_FUTURE,
        )
        later shouldNotBe entry()
        later.attributes shouldBe emptyMap()
        shouldThrow<IllegalArgumentException> {
            entry(attributes = (1..TOO_MANY).associate { index -> "$index" to "v" })
        }
    }

    test("the text of an entry escapes hostile subjects and attributes") {
        HostileFragments.all.forEach { hostile ->
            val shown = entry(subject = hostile, attributes = mapOf(hostile to hostile)).toString()
            isSafeToShow(shown) shouldBe true
        }
    }
})
