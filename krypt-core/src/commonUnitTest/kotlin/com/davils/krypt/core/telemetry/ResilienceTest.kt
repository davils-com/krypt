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

import com.davils.kollect.core.meterRegistry
import com.davils.kollect.core.trace.Tracer
import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.Environment
import com.davils.krypt.core.environment
import com.davils.krypt.core.fixture.withBus
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe

class ResilienceTest : FunSpec({
    context("the environment of kontinuity") {
        test("reports to the meters, the event bus and the tracer of krypt") {
            withBus { bus ->
                val registry = meterRegistry()
                val source = environment {
                    meters(registry)
                    events(bus)
                }

                val resilience = source.resilience()

                resilience.meters shouldBe registry
                resilience.events shouldBe bus
                resilience.tracer shouldBe source.tracer
            }
        }

        test("reports nowhere for an environment without telemetry") {
            val resilience = Environment.Default.resilience()

            resilience.meters.shouldBeNull()
            resilience.events.shouldBeNull()
            resilience.tracer shouldBe Tracer.None
        }
    }
})
