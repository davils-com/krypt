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

import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.name.GeneralName

/**
 * Where a revocation list of a certificate is published.
 *
 * @property names the full names of the list, such as an HTTP URI.
 * @property reasons the reasons the list covers, or null for every reason.
 * @property crlIssuer the issuer of the list when it is not the issuer of the certificate, or an empty list.
 * @constructor Names a distribution point.
 * @since 1.0.0
 */
public class DistributionPoint(
    public val names: List<GeneralName>,
    public val reasons: Set<RevocationReason>? = null,
    public val crlIssuer: List<GeneralName> = emptyList(),
) {
    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same point.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is DistributionPoint &&
        listOf(
            names,
            reasons,
            crlIssuer,
        ) == listOf(other.names, other.reasons, other.crlIssuer)

    /**
     * Hashes the names.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = names.hashCode()

    /**
     * Shows the names.
     *
     * @return the point as text.
     * @since 1.0.0
     */
    override fun toString(): String = "DistributionPoint($names)"
}
