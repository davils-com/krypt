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

package com.davils.krypt.tls.reload

import com.davils.konfetti.core.TopicKey
import com.davils.krypt.core.CryptoEvent
import com.davils.krypt.keystore.material.MaterialFailure

/**
 * The event of a reload of TLS material, sent on [TOPIC] of the event bus of the environment and on the events of the
 * [MaterialReloader]. It names no material, only what happened.
 *
 * @property action what the reload did.
 * @property generation the generation in use afterwards: the new one after a reload, the last good one after a
 *   failure.
 * @property failure why loading failed, or null.
 * @since 1.0.0
 */
public class ReloadEvent internal constructor(
    public val action: ReloadAction,
    public val generation: Long,
    public val failure: MaterialFailure?,
) : CryptoEvent {
    override val component: String get() = COMPONENT

    private val values: List<Any?> get() = listOf(action, generation, failure)

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same event.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is ReloadEvent && values == other.values

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows every property.
     *
     * @return the event as text.
     * @since 1.0.0
     */
    override fun toString(): String = "ReloadEvent($action, generation=$generation, failure=${failure ?: NONE})"

    /**
     * The topic of the events.
     *
     * @since 1.0.0
     */
    public companion object {
        private const val COMPONENT: String = "tls"
        private const val NONE: String = "none"

        /**
         * The topic of reloads of TLS material.
         *
         * @since 1.0.0
         */
        public val TOPIC: TopicKey<ReloadEvent> = TopicKey("krypt.tls.reload")
    }
}
