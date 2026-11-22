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

package com.davils.krypt.tls.trust

import com.davils.krypt.ct.CtPolicy
import com.davils.krypt.ct.LogList

/**
 * The Certificate Transparency a peer must show: signed certificate timestamps of the [logs] that satisfy the
 * [policy].
 *
 * The timestamps are read from the certificate and from a stapled OCSP response. JSSE gives no access to the
 * timestamps of the TLS extension, so a peer that sends them only there does not satisfy the policy.
 *
 * @property logs the logs the application trusts.
 * @property policy how many timestamps and operators are required.
 * @constructor Requires transparency.
 * @since 1.0.0
 */
public class TransparencyRequirement(public val logs: LogList, public val policy: CtPolicy = CtPolicy.Default) {
    private val values: List<Any?> get() = listOf(logs, policy)

    /**
     * Compares the logs and the policy.
     *
     * @param other the other object.
     * @return true if [other] requires the same.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is TransparencyRequirement && values == other.values

    /**
     * Hashes the logs and the policy.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the logs and the policy.
     *
     * @return the requirement as text.
     * @since 1.0.0
     */
    override fun toString(): String = "TransparencyRequirement($logs, $policy)"
}
