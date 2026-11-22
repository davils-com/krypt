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

@file:OptIn(ExperimentalAtomicApi::class)

package com.davils.krypt.core.telemetry

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.failure.attempted
import com.davils.krypt.core.Environment
import com.davils.krypt.core.audit.AuditAction
import com.davils.krypt.core.audit.AuditEntry
import com.davils.krypt.core.audit.AuditOutcome
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Records the audited actions of a component in the audit sink of its environment.
 *
 * A failure of the sink is contained: it is counted in [failures] and reported by [record], which a component with a
 * required audit turns into a refusal of the operation.
 *
 * @param environment the environment of the component.
 * @since 1.0.0
 */
@DavilsInternal
public class AuditTrail(private val environment: Environment) {
    private val failureCount = AtomicLong(0L)

    /**
     * How many entries the sink failed to record.
     *
     * @since 1.0.0
     */
    public val failures: Long get() = failureCount.load()

    /**
     * Records an entry for [action] on [subject].
     *
     * @param action what happened.
     * @param subject what it happened to.
     * @param outcome how it ended.
     * @param attributes further facts.
     * @return false if the entry could not be recorded and the audit is required, which refuses the operation; true
     *   otherwise.
     * @since 1.0.0
     */
    public suspend fun record(
        action: AuditAction,
        subject: String,
        outcome: AuditOutcome,
        attributes: Map<String, String> = emptyMap(),
    ): Boolean {
        val sink = environment.audit ?: return true
        val entry = AuditEntry(
            action = action,
            subject = subject,
            outcome = outcome,
            at = environment.clock.now(),
            attributes = attributes,
        )
        val recorded = attempted { sink.record(entry) }
        recorded.onFailure { failureCount.addAndFetch(1L) }
        return recorded.isSuccess || !environment.isAuditRequired
    }
}
