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

package com.davils.krypt.testing

import com.davils.krypt.core.audit.AuditAction
import com.davils.krypt.core.audit.AuditEntry
import com.davils.krypt.core.audit.AuditSink
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * An [AuditSink] for tests that keeps every entry in memory, or refuses every entry when [isFailing] is set.
 *
 * The log is safe to share between coroutines.
 *
 * @property isFailing whether every entry is refused with an [IllegalStateException].
 * @constructor Starts an empty log.
 * @since 1.0.0
 */
public class AuditLog(public val isFailing: Boolean = false) : AuditSink {
    private val lock = Mutex()
    private val recorded = mutableListOf<AuditEntry>()

    /**
     * Every entry recorded so far, oldest first.
     *
     * @since 1.0.0
     */
    public val entries: List<AuditEntry> get() = recorded.toList()

    /**
     * Records [entry], or throws when the log [isFailing].
     *
     * @param entry what happened.
     * @throws IllegalStateException if the log is failing.
     * @since 1.0.0
     */
    override suspend fun record(entry: AuditEntry) {
        check(!isFailing) { "The audit log refuses every entry" }
        lock.withLock { recorded += entry }
    }

    /**
     * Returns the entries of [action].
     *
     * @param action the action.
     * @return the entries of [action], oldest first.
     * @since 1.0.0
     */
    public fun of(action: AuditAction): List<AuditEntry> = entries.filter { entry -> entry.action == action }

    /**
     * Shows the number of entries.
     *
     * @return the log as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AuditLog(${recorded.size} entries)"
}
