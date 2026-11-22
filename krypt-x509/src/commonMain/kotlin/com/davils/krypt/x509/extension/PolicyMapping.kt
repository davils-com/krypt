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

import com.davils.krypt.asn1.ObjectIdentifier

/**
 * One policy mapping: the policy of the issuer that the policy of the subject is equivalent to.
 *
 * @property issuerPolicy the policy in the domain of the issuer.
 * @property subjectPolicy the equivalent policy in the domain of the subject.
 * @constructor Maps [issuerPolicy] to [subjectPolicy].
 * @since 1.0.0
 */
public class PolicyMapping(public val issuerPolicy: ObjectIdentifier, public val subjectPolicy: ObjectIdentifier) {
    /**
     * Compares both policies.
     *
     * @param other the other object.
     * @return true if [other] is the same mapping.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is PolicyMapping && issuerPolicy == other.issuerPolicy && subjectPolicy == other.subjectPolicy

    /**
     * Hashes both policies.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(issuerPolicy, subjectPolicy).hashCode()

    /**
     * Shows both policies.
     *
     * @return the mapping as text.
     * @since 1.0.0
     */
    override fun toString(): String = "PolicyMapping(${issuerPolicy.dotted} -> ${subjectPolicy.dotted})"
}
