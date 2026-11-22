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

package com.davils.krypt.core

import com.davils.kollect.core.MeterRegistry
import com.davils.kollect.core.trace.Tracer
import com.davils.konfetti.core.EventBus
import com.davils.kore.core.annotation.DavilsDsl
import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.dsl.ValidatingBuilder
import com.davils.krypt.core.audit.AuditSink
import com.davils.krypt.core.policy.CryptoPolicy
import kotlin.time.Clock

/**
 * Builds an [Environment]; every property starts from the environment [environment] starts from.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class EnvironmentBuilder internal constructor() : ValidatingBuilder<Environment>() {
    override val subject: String get() = "environment"

    /**
     * See [Environment.random].
     *
     * @since 1.0.0
     */
    public var random: RandomSource = RandomSource.Secure
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [Environment.clock].
     *
     * @since 1.0.0
     */
    public var clock: Clock = Clock.System
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [Environment.policy].
     *
     * @since 1.0.0
     */
    public var policy: CryptoPolicy = CryptoPolicy.Modern
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [Environment.tracer].
     *
     * @since 1.0.0
     */
    public var tracer: Tracer = Tracer.None
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [Environment.isAuditRequired].
     *
     * @since 1.0.0
     */
    public var isAuditRequired: Boolean = false
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [Environment.eventCapacity].
     *
     * @since 1.0.0
     */
    public var eventCapacity: Int = Environment.DEFAULT_EVENT_CAPACITY
        set(value) {
            checkOpen()
            field = value
        }

    internal var events: EventBus? = null
        private set

    internal var meters: MeterRegistry? = null
        private set

    internal var audit: AuditSink? = null
        private set

    internal var platformProvider: Any? = null
        private set

    /**
     * Publishes the events of every component on the topics of [bus], too; see [Environment.events].
     *
     * @param bus the event bus.
     * @throws IllegalStateException if this builder was evaluated already.
     * @since 1.0.0
     */
    public fun events(bus: EventBus) {
        checkOpen()
        events = bus
    }

    /**
     * Records the meters of every component in [registry]; see [Environment.meters].
     *
     * @param registry the meter registry.
     * @throws IllegalStateException if this builder was evaluated already.
     * @since 1.0.0
     */
    public fun meters(registry: MeterRegistry) {
        checkOpen()
        meters = registry
    }

    /**
     * Records audited actions in [sink]; see [Environment.audit].
     *
     * @param sink the audit sink.
     * @param required whether an operation that cannot record its entry is refused; see [Environment.isAuditRequired].
     * @throws IllegalStateException if this builder was evaluated already.
     * @since 1.0.0
     */
    public fun audit(sink: AuditSink, required: Boolean = isAuditRequired) {
        checkOpen()
        audit = sink
        isAuditRequired = required
    }

    /**
     * Sets the platform provider; the JVM wraps this in `provider(java.security.Provider)`.
     *
     * @param provider the provider.
     * @throws IllegalStateException if this builder was evaluated already.
     * @since 1.0.0
     */
    @DavilsInternal
    public fun platformProvider(provider: Any) {
        checkOpen()
        platformProvider = provider
    }

    internal fun from(base: Environment) {
        random = base.random
        clock = base.clock
        policy = base.policy
        tracer = base.tracer
        isAuditRequired = base.isAuditRequired
        eventCapacity = base.eventCapacity
        events = base.events
        meters = base.meters
        audit = base.audit
        platformProvider = base.platformProvider
    }

    override fun assemble(): Environment = Environment(this)
}
