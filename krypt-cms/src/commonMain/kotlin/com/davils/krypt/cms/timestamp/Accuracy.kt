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

package com.davils.krypt.cms.timestamp

import kotlin.time.Duration
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The accuracy of the time of a time-stamp token by RFC 3161: the time lies within this deviation of the stated one.
 *
 * @property seconds the whole seconds, not negative.
 * @property millis the milliseconds, 0 to 999.
 * @property micros the microseconds, 0 to 999.
 * @constructor Describes the accuracy.
 * @throws IllegalArgumentException if a field is out of range or all are zero.
 * @since 1.0.0
 */
public class Accuracy(public val seconds: Int = 0, public val millis: Int = 0, public val micros: Int = 0) {
    init {
        require(seconds >= 0 && millis in 0..MAXIMUM_PART && micros in 0..MAXIMUM_PART) {
            "An accuracy has non-negative seconds and 0 to 999 milliseconds and microseconds"
        }
        require(seconds.toLong() + millis + micros > 0) { "An accuracy is not zero" }
    }

    /**
     * The accuracy as a duration.
     *
     * @since 1.0.0
     */
    public val duration: Duration get() = seconds.seconds + millis.milliseconds + micros.microseconds

    /**
     * Compares every field.
     *
     * @param other the other object.
     * @return true if [other] is the same accuracy.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is Accuracy && listOf(seconds, millis, micros) == listOf(other.seconds, other.millis, other.micros)

    /**
     * Hashes every field.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(seconds, millis, micros).hashCode()

    /**
     * Shows the accuracy as a duration.
     *
     * @return the accuracy as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Accuracy($duration)"

    private companion object {
        const val MAXIMUM_PART: Int = 999
    }
}
