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

package com.davils.krypt.keyset

import com.davils.konfetti.core.TopicKey
import com.davils.krypt.core.CryptoEvent

/**
 * Tells that [action] happened to the key [keyId] of a key set.
 *
 * @property action what happened.
 * @property keyId the key it happened to.
 * @since 1.0.0
 */
public class KeysetEvent internal constructor(public val action: KeysetAction, public val keyId: KeyId) : CryptoEvent {
    override val component: String get() = COMPONENT

    /**
     * Compares the action and the key.
     *
     * @param other the other object.
     * @return true if [other] tells the same.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is KeysetEvent && action == other.action && keyId == other.keyId

    /**
     * Hashes the action and the key.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(action, keyId).hashCode()

    /**
     * Shows the action and the key.
     *
     * @return the event as text.
     * @since 1.0.0
     */
    override fun toString(): String = "KeysetEvent($action, $keyId)"

    /**
     * The topic of the events.
     *
     * @since 1.0.0
     */
    public companion object {
        private const val COMPONENT: String = "keyset"

        /**
         * The topic the events of key sets are published to when the environment names an event bus.
         *
         * @since 1.0.0
         */
        public val TOPIC: TopicKey<KeysetEvent> = TopicKey("krypt.keyset")
    }
}
