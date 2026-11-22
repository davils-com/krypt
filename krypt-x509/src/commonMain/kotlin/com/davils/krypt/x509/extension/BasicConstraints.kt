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

package com.davils.krypt.x509.extension

/**
 * The basic constraints: whether the subject is a certificate authority and how many authorities may follow it.
 *
 * @property isCa whether the subject is a certificate authority.
 * @property pathLength the most intermediate authorities below the subject, or null for no limit.
 * @constructor Holds the constraints.
 * @throws IllegalArgumentException if [pathLength] is negative or given for an end entity.
 * @since 1.0.0
 */
public class BasicConstraints(public val isCa: Boolean, public val pathLength: Int? = null) {
    init {
        require(pathLength == null || (isCa && pathLength >= 0)) { "Only an authority has a path length of 0 or more" }
    }

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] are the same constraints.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is BasicConstraints && isCa == other.isCa && pathLength == other.pathLength

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(isCa, pathLength).hashCode()

    /**
     * Shows every property.
     *
     * @return the constraints as text.
     * @since 1.0.0
     */
    override fun toString(): String = "BasicConstraints(ca=$isCa, pathLength=${pathLength ?: "none"})"
}
