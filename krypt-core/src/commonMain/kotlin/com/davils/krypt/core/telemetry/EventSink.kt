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

package com.davils.krypt.core.telemetry

import com.davils.konfetti.core.TopicKey
import com.davils.konfetti.core.publish.Emitter
import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.CryptoEvent
import com.davils.krypt.core.Environment
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/**
 * Where a component sends its events: a `Flow` of its own and, when the environment names an event bus, the topic
 * [key] on it.
 *
 * Emitting never waits and never throws: an event is built only when someone listens, the oldest event is dropped when
 * a listener of the flow falls behind, and an event the topic refuses is counted in [rejected].
 *
 * @param E the type of the events.
 * @param environment the environment of the component.
 * @param key the topic of the component; it is declared on the bus if it is missing. Since 1.1.0 a bus that declares
 * [key] for another event type no longer fails the component: its events then reach the flow only.
 * @since 1.0.0
 */
@DavilsInternal
public class EventSink<E : CryptoEvent>(environment: Environment, key: TopicKey<E>) {
    private val local = MutableSharedFlow<E>(
        extraBufferCapacity = environment.eventCapacity,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    private val emitter: Emitter<E>? = environment.events?.let { bus -> Emitter(bus, key) }

    /**
     * The events, hot and without replay: a collector sees the events emitted while it collects.
     *
     * @since 1.0.0
     */
    public val events: Flow<E> = local.asSharedFlow()

    /**
     * How many events the topic refused or could not take.
     *
     * @since 1.0.0
     */
    public val rejected: Long get() = emitter?.rejected ?: 0L

    /**
     * Tells whether a collector of [events] or a consumer of the topic would see an event now.
     *
     * @since 1.0.0
     */
    public val isListened: Boolean get() = local.subscriptionCount.value > 0 || emitter?.hasConsumers == true

    /**
     * Builds an event with [event] and sends it, but only when someone listens.
     *
     * @param event builds the event.
     * @since 1.0.0
     */
    public inline fun emit(event: () -> E) {
        if (isListened) send(event())
    }

    /**
     * Sends [event] to the flow and the topic.
     *
     * @param event the event.
     * @since 1.0.0
     */
    public fun send(event: E) {
        local.tryEmit(event)
        emitter?.send(event)
    }
}
