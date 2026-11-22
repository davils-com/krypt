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

package com.davils.krypt.ct

/**
 * The verification of one signed certificate timestamp.
 *
 * @property timestamp the timestamp.
 * @property origin where it came from.
 * @property log the log it names, or null if the log is unknown.
 * @property status the outcome.
 * @since 1.0.0
 */
public class SctResult internal constructor(
    public val timestamp: SignedCertificateTimestamp,
    public val origin: SctOrigin,
    public val log: CtLog?,
    public val status: SctStatus,
) {
    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same result.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is SctResult &&
        listOf(timestamp, origin, log, status) == listOf(other.timestamp, other.origin, other.log, other.status)

    /**
     * Hashes the timestamp.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = timestamp.hashCode()

    /**
     * Shows the origin and the status.
     *
     * @return the result as text.
     * @since 1.0.0
     */
    override fun toString(): String = "SctResult($origin, $status)"
}
