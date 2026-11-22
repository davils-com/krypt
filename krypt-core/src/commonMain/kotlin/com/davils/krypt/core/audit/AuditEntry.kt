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

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import kotlin.time.Instant

private const val MAXIMUM_ATTRIBUTES: Int = 32

/**
 * One audited action: what happened to what, when, and how it ended.
 *
 * The subject and the attributes name things, such as the id of a key or the serial number of a certificate, and
 * never carry key material or plaintext.
 *
 * @property action what happened.
 * @property subject what it happened to, such as `keyset:payments/key:7`.
 * @property outcome how it ended.
 * @property at when it happened, by the clock of the environment.
 * @param attributes further facts, such as the algorithm or the reason of a refusal; at most 32.
 * @since 1.0.0
 */
@OptIn(DavilsInternal::class)
public class AuditEntry(
    public val action: AuditAction,
    public val subject: String,
    public val outcome: AuditOutcome,
    public val at: Instant,
    attributes: Map<String, String> = emptyMap(),
) {
    /**
     * Further facts, such as the algorithm or the reason of a refusal, sorted by name.
     *
     * @since 1.0.0
     */
    public val attributes: Map<String, String> = buildMap {
        attributes.keys.sorted().forEach { name -> put(key = name, value = attributes.getValue(name)) }
    }

    init {
        require(attributes.size <= MAXIMUM_ATTRIBUTES) { "An audit entry holds at most $MAXIMUM_ATTRIBUTES attributes" }
    }

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same entry.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is AuditEntry &&
        action == other.action &&
        subject == other.subject &&
        outcome == other.outcome &&
        at == other.at &&
        attributes == other.attributes

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(action, subject, outcome, at, attributes).hashCode()

    /**
     * Shows the entry, with the subject and the attributes escaped.
     *
     * @return the entry as text.
     * @since 1.0.0
     */
    override fun toString(): String {
        val shown = attributes.entries.joinToString { (name, value) ->
            "${SafeText.text(
                name,
            )}=${SafeText.text(value)}"
        }
        return "AuditEntry($action, subject=${SafeText.text(subject)}, outcome=$outcome, at=$at, attributes={$shown})"
    }
}
