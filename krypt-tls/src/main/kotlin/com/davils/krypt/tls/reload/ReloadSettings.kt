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

import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

/**
 * The timing of a [MaterialReloader] that watches changes.
 *
 * @property debounce how long the changes must be quiet before a reload starts, so a burst of changes, such as the
 *   files of a rotation written one after another, loads once.
 * @property holdDown the shortest time between two reloads, so changes in a loop cannot load without pause.
 * @property expiryWarning how long before its end a certificate counts as [ExpiryState.Expiring].
 * @constructor Describes the timing.
 * @throws IllegalArgumentException if [debounce] or [holdDown] is negative or longer than [HARD_MAXIMUM_DELAY], or
 *   [expiryWarning] is negative or longer than [HARD_MAXIMUM_WARNING].
 * @since 1.0.0
 */
public class ReloadSettings(
    public val debounce: Duration = DEFAULT_DEBOUNCE_SECONDS.seconds,
    public val holdDown: Duration = DEFAULT_HOLD_DOWN_SECONDS.seconds,
    public val expiryWarning: Duration = DEFAULT_WARNING_DAYS.days,
) {
    init {
        val delays = listOf(debounce, holdDown)
        require(delays.all { delay -> !delay.isNegative() && delay <= HARD_MAXIMUM_DELAY }) {
            "A debounce and a hold-down last zero to $HARD_MAXIMUM_DELAY"
        }
        require(!expiryWarning.isNegative() && expiryWarning <= HARD_MAXIMUM_WARNING) {
            "An expiry warning lasts zero to $HARD_MAXIMUM_WARNING"
        }
    }

    private val values: List<Any?> get() = listOf(debounce, holdDown, expiryWarning)

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] describes the same timing.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is ReloadSettings && values == other.values

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
     * @return the settings as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "ReloadSettings(debounce=$debounce, holdDown=$holdDown, expiryWarning=$expiryWarning)"

    /**
     * The defaults and bounds of the timing.
     *
     * @since 1.0.0
     */
    public companion object {
        private const val DEFAULT_DEBOUNCE_SECONDS: Int = 2
        private const val DEFAULT_HOLD_DOWN_SECONDS: Int = 30
        private const val DEFAULT_WARNING_DAYS: Int = 30

        /**
         * The longest debounce and hold-down.
         *
         * @since 1.0.0
         */
        public val HARD_MAXIMUM_DELAY: Duration = 1.hours

        /**
         * The longest expiry warning.
         *
         * @since 1.0.0
         */
        public val HARD_MAXIMUM_WARNING: Duration = 365.days
    }
}
