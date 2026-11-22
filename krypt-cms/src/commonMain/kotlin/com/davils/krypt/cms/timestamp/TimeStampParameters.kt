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

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.signed.SignatureParameters

/**
 * What the verification of a time-stamp token expects.
 *
 * @property signature the certificates and the path validation of the authority's certificate; without a path
 *   validator anybody's token passes.
 * @property nonce the nonce the token must carry, or null for none.
 * @property policy the policy the token must name, or null for any.
 * @property isCertificateRequired true if the token must carry the authority's certificate.
 * @constructor Describes the expectations.
 * @since 1.0.0
 */
public class TimeStampParameters(
    public val signature: SignatureParameters = SignatureParameters(),
    public val nonce: DerInteger? = null,
    public val policy: ObjectIdentifier? = null,
    public val isCertificateRequired: Boolean = false,
) {
    private val values: List<Any?> get() = listOf(signature, nonce, policy, isCertificateRequired)

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] has the same expectations.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is TimeStampParameters && values == other.values

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the expectations.
     *
     * @return the parameters as text.
     * @since 1.0.0
     */
    override fun toString(): String = "TimeStampParameters($signature, nonce=${nonce != null}, " +
        "policy=${policy?.dotted.orEmpty()}, certificate=$isCertificateRequired)"
}
