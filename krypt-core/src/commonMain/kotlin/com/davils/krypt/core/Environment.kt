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
import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.kore.core.validation.inRange
import com.davils.kore.core.validation.validateOrThrow
import com.davils.krypt.core.audit.AuditSink
import com.davils.krypt.core.policy.CryptoPolicy
import kotlin.time.Clock

private const val SUBJECT: String = "environment"

/**
 * What krypt takes from its surroundings: the randomness, the clock, the policy, the event bus, the meter registry,
 * the tracer and the audit trail.
 *
 * An environment holds no state of its own, so one environment can serve a whole application. Without an event bus the
 * events of a component are only a `Flow`, without a meter registry it records no meters, and without an audit sink it
 * audits nothing.
 *
 * @since 1.0.0
 */
public class Environment internal constructor(builder: EnvironmentBuilder) : Validatable {
    /**
     * The randomness of every key, nonce, salt and serial number; [RandomSource.Secure] by default.
     *
     * @since 1.0.0
     */
    public val random: RandomSource = builder.random

    /**
     * The clock of validity periods, expiry and audit entries; [Clock.System] by default.
     *
     * @since 1.0.0
     */
    public val clock: Clock = builder.clock

    /**
     * The policy every operation asks first; [CryptoPolicy.Modern] by default.
     *
     * @since 1.0.0
     */
    public val policy: CryptoPolicy = builder.policy

    /**
     * The event bus whose topics carry the events of every component, or null for none.
     *
     * @since 1.0.0
     */
    public val events: EventBus? = builder.events

    /**
     * The meter registry every component records its meters in, or null for none.
     *
     * @since 1.0.0
     */
    public val meters: MeterRegistry? = builder.meters

    /**
     * The tracer that opens a span for the long operations, such as streaming encryption or path validation;
     * [Tracer.None] by default.
     *
     * @since 1.0.0
     */
    public val tracer: Tracer = builder.tracer

    /**
     * Where audited actions are recorded, or null for none.
     *
     * @since 1.0.0
     */
    public val audit: AuditSink? = builder.audit

    /**
     * Tells whether an operation that cannot record its audit entry is refused (true) or carries on (false, the
     * default). Without an [audit] sink nothing is recorded and nothing is refused.
     *
     * @since 1.0.0
     */
    public val isAuditRequired: Boolean = builder.isAuditRequired

    /**
     * How many events of one component wait for a slow listener of its `Flow` before the oldest is dropped: 64 by
     * default, from 1 to [HARD_EVENT_CAPACITY].
     *
     * @since 1.0.0
     */
    public val eventCapacity: Int = builder.eventCapacity

    /**
     * The JCA provider of the JVM backend as set by `provider(…)` on the JVM, or null for the default providers.
     *
     * @since 1.0.0
     */
    @DavilsInternal
    public val platformProvider: Any? = builder.platformProvider

    init {
        validateOrThrow(SUBJECT)
    }

    /**
     * Checks that [eventCapacity] is within its bounds.
     *
     * @receiver the validation that collects the violations.
     * @since 1.0.0
     */
    override fun ValidationScope.validate() {
        inRange(property = ::eventCapacity, value = eventCapacity, range = 1..HARD_EVENT_CAPACITY)
    }

    /**
     * Shows the policy and which parts of the environment are set.
     *
     * @return the environment as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "Environment(policy=${policy.profile}, events=${events != null}, meters=${meters != null}, " +
            "audit=${audit != null}, isAuditRequired=$isAuditRequired, provider=${platformProvider != null}, " +
            "eventCapacity=$eventCapacity)"

    /**
     * The hard ceiling and the default environment.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The hard ceiling of [eventCapacity]: 4,096.
         *
         * @since 1.0.0
         */
        public const val HARD_EVENT_CAPACITY: Int = 4_096

        internal const val DEFAULT_EVENT_CAPACITY: Int = 64

        /**
         * The environment with secure randomness, the system clock, the modern policy, no event bus, no meter
         * registry, no tracer, no audit sink and the default providers.
         *
         * @since 1.0.0
         */
        public val Default: Environment = Environment(EnvironmentBuilder())
    }
}
