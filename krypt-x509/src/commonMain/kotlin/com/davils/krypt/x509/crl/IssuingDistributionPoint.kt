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

package com.davils.krypt.x509.crl

import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.name.GeneralName

/**
 * The issuing distribution point of a revocation list: which certificates and reasons the list covers.
 *
 * @property names the names of the distribution point, or an empty list.
 * @property isUserOnly whether the list covers end entities only.
 * @property isCaOnly whether the list covers authorities only.
 * @property onlySomeReasons the reasons the list covers, or null for every reason.
 * @property isIndirect whether the list holds certificates of other issuers.
 * @constructor Describes the scope of a list.
 * @throws IllegalArgumentException if both only-flags are set.
 * @since 1.0.0
 */
public class IssuingDistributionPoint(
    public val names: List<GeneralName> = emptyList(),
    public val isUserOnly: Boolean = false,
    public val isCaOnly: Boolean = false,
    public val onlySomeReasons: Set<RevocationReason>? = null,
    public val isIndirect: Boolean = false,
) {
    init {
        require(!(isUserOnly && isCaOnly)) { "A list covers end entities or authorities or both" }
    }

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same point.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is IssuingDistributionPoint &&
        listOf(names, isUserOnly, isCaOnly, onlySomeReasons, isIndirect) ==
        listOf(
            other.names,
            other.isUserOnly,
            other.isCaOnly,
            other.onlySomeReasons,
            other.isIndirect,
        )

    /**
     * Hashes the names.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = names.hashCode()

    /**
     * Shows every property.
     *
     * @return the point as text.
     * @since 1.0.0
     */
    override fun toString(): String = "IssuingDistributionPoint($names, user=$isUserOnly, " +
        "ca=$isCaOnly, reasons=${onlySomeReasons ?: "all"}, indirect=$isIndirect)"
}
