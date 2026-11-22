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

package com.davils.krypt.core.telemetry

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.Environment
import com.davils.krypt.core.audit.AuditAction
import com.davils.krypt.core.audit.AuditEntry
import com.davils.krypt.core.audit.AuditOutcome
import com.davils.krypt.core.environment
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlin.time.Clock
import kotlin.time.Instant

private const val SUBJECT: String = "subject"
private val ACTION: AuditAction = AuditAction("probe.done")
private val NOW: Instant = Instant.fromEpochSeconds(2)

class AuditTrailTest : FunSpec({
    val fixed = object : Clock {
        override fun now(): Instant = NOW
    }

    test("without a sink nothing is recorded and nothing is refused") {
        val trail = AuditTrail(Environment.Default)
        trail.record(action = ACTION, subject = SUBJECT, outcome = AuditOutcome.Succeeded) shouldBe true
        trail.failures shouldBe 0L
    }

    test("an entry reaches the sink with the time of the clock") {
        val entries = mutableListOf<AuditEntry>()
        val trail = AuditTrail(
            environment {
                clock = fixed
                audit({ entry -> entries += entry })
            },
        )
        val attributes = mapOf("reason" to "policy")
        trail.record(
            action = ACTION,
            subject = SUBJECT,
            outcome = AuditOutcome.Refused,
            attributes = attributes,
        ) shouldBe
            true
        entries.single().at shouldBe NOW
        entries.single().attributes shouldBe attributes
    }

    test("a failing sink is counted and refuses only a required audit") {
        val failing = environment { audit({ _ -> error("the audit store is down") }) }
        val bestEffort = AuditTrail(failing)
        bestEffort.record(action = ACTION, subject = SUBJECT, outcome = AuditOutcome.Succeeded) shouldBe true
        bestEffort.failures shouldBe 1L
        val required = AuditTrail(environment(failing) { isAuditRequired = true })
        required.record(action = ACTION, subject = SUBJECT, outcome = AuditOutcome.Succeeded) shouldBe false
        required.failures shouldBe 1L
    }
})
