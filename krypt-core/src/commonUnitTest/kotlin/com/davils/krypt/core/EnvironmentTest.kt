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

package com.davils.krypt.core

import com.davils.kollect.core.meterRegistry
import com.davils.kollect.core.trace.Tracer
import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.core.fixture.withBus
import com.davils.krypt.core.policy.CryptoPolicy
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlin.time.Clock

class EnvironmentTest : FunSpec({
    test("the default environment is secure, modern and silent") {
        val environment = Environment.Default
        environment.random shouldBeSameInstanceAs RandomSource.Secure
        environment.clock shouldBeSameInstanceAs Clock.System
        environment.policy shouldBeSameInstanceAs CryptoPolicy.Modern
        environment.events shouldBe null
        environment.meters shouldBe null
        environment.audit shouldBe null
        environment.isAuditRequired shouldBe false
        environment.tracer shouldBeSameInstanceAs Tracer.None
        environment.toString() shouldBe "Environment(policy=Modern, events=false, meters=false, audit=false, " +
            "isAuditRequired=false, provider=false, eventCapacity=64)"
    }

    test("an environment starts from its base and changes what is set") {
        withBus { bus ->
            val registry = meterRegistry {}
            val random = RandomSource { target -> target.fill(1) }
            val base = environment {
                events(bus)
                meters(registry)
                this.random = random
                policy = CryptoPolicy.Cnsa2
                eventCapacity = 2
                tracer = Tracer.None
                audit({ _ -> }, required = true)
            }
            val derived = environment(base) { policy = CryptoPolicy.Fips }
            derived.events shouldBeSameInstanceAs bus
            derived.meters shouldBeSameInstanceAs registry
            derived.random shouldBeSameInstanceAs random
            derived.policy shouldBeSameInstanceAs CryptoPolicy.Fips
            derived.eventCapacity shouldBe 2
            derived.isAuditRequired shouldBe true
        }
    }

    test("an event capacity outside its bounds is refused") {
        shouldThrow<ValidationException> { environment { eventCapacity = 0 } }
        shouldThrow<ValidationException> { environment { eventCapacity = Environment.HARD_EVENT_CAPACITY + 1 } }
    }

    test("a built builder refuses further changes") {
        val builder = EnvironmentBuilder()
        builder.build()
        shouldThrow<IllegalStateException> { builder.clock = Clock.System }
        shouldThrow<IllegalStateException> { builder.audit({ _ -> }) }
    }
})
