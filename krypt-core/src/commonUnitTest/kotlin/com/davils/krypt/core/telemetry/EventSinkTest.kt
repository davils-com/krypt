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

import com.davils.konfetti.testing.EventRecorder
import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.Environment
import com.davils.krypt.core.environment
import com.davils.krypt.core.fixture.ProbeEvent
import com.davils.krypt.core.fixture.withBus
import io.kotest.common.ExperimentalKotest
import io.kotest.core.spec.style.FunSpec
import io.kotest.core.test.testCoroutineScheduler
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch

private const val THREE: Int = 3

@OptIn(ExperimentalKotest::class)
class EventSinkTest : FunSpec({
    coroutineTestScope = true

    test("an event nobody listens to is never built") {
        val sink = EventSink(Environment.Default, ProbeEvent.TOPIC)
        var built = 0
        sink.emit {
            built += 1
            ProbeEvent(1)
        }
        built shouldBe 0
        sink.isListened shouldBe false
    }

    test("a collector of the flow sees the events emitted while it collects") {
        val sink = EventSink(Environment.Default, ProbeEvent.TOPIC)
        val seen = mutableListOf<Int>()
        val collector = launch(
            start = CoroutineStart.UNDISPATCHED,
        ) { sink.events.collect { event -> seen += event.sequence } }
        sink.isListened shouldBe true
        sink.emit { ProbeEvent(1) }
        sink.emit { ProbeEvent(2) }
        testCoroutineScheduler.runCurrent()
        collector.cancel()
        seen shouldBe listOf(1, 2)
    }

    test("a slow collector loses the oldest events") {
        val sink = EventSink(environment { eventCapacity = 1 }, ProbeEvent.TOPIC)
        val seen = mutableListOf<Int>()
        val collector = launch(
            start = CoroutineStart.UNDISPATCHED,
        ) { sink.events.collect { event -> seen += event.sequence } }
        repeat(THREE) { index -> sink.send(ProbeEvent(index + 1)) }
        testCoroutineScheduler.runCurrent()
        collector.cancel()
        seen.last() shouldBe THREE
    }

    test("the topic on the bus receives the events and a refused event is counted") {
        withBus { bus ->
            val sink = EventSink(environment { events(bus) }, ProbeEvent.TOPIC)
            val recorder = EventRecorder<ProbeEvent>()
            bus[ProbeEvent.TOPIC].consume("recorder") { handle(recorder::record) }
            sink.isListened shouldBe true
            sink.emit { ProbeEvent(1) }
            recorder.awaitCount(1)
            recorder.payloads.single().sequence shouldBe 1
            bus.abort()
            sink.send(ProbeEvent(2))
            sink.rejected shouldBe 1L
        }
    }

    test("a second sink of the same kind finds the declared topic") {
        withBus { bus ->
            val environment = environment { events(bus) }
            bus.declare(ProbeEvent.TOPIC)
            val sink = EventSink(environment, ProbeEvent.TOPIC)
            sink.isListened shouldBe false
            sink.send(ProbeEvent(1))
            sink.rejected shouldBe 0L
        }
    }
})
