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

package com.davils.krypt.x509.path

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.extension.KeyPurposes
import kotlin.time.Instant

/**
 * What a path validation checks besides the rules of RFC 5280.
 *
 * @property at the time of validation, or null for the clock of the environment.
 * @property purpose the key purpose the end entity must allow, such as [KeyPurposes.ServerAuth], or null for any;
 *   an authority with an extended key usage must allow it, too.
 * @property initialPolicies the acceptable certificate policies; anyPolicy by default.
 * @property isExplicitPolicyRequired whether the path must be valid for an acceptable policy.
 * @property isPolicyMappingInhibited whether policy mappings are refused.
 * @property isAnyPolicyInhibited whether anyPolicy in a certificate counts for nothing.
 * @property isRevocationRequired whether an unknown revocation status of the [RevocationChecker] of the
 *   [PathValidator] fails the validation; false soft-fails. It needs a checker: a validator without one checks no
 *   revocation at all, whatever this says.
 * @constructor Describes the validation.
 * @throws IllegalArgumentException if [initialPolicies] is empty.
 * @since 1.0.0
 */
public class ValidationParameters(
    public val at: Instant? = null,
    public val purpose: ObjectIdentifier? = null,
    public val initialPolicies: Set<ObjectIdentifier> = setOf(KeyPurposes.AnyPolicy),
    public val isExplicitPolicyRequired: Boolean = false,
    public val isPolicyMappingInhibited: Boolean = false,
    public val isAnyPolicyInhibited: Boolean = false,
    public val isRevocationRequired: Boolean = true,
) {
    private val values: List<Any?>
        get() = listOf(
            at,
            purpose,
            initialPolicies,
            isExplicitPolicyRequired,
            isPolicyMappingInhibited,
            isAnyPolicyInhibited,
            isRevocationRequired,
        )

    init {
        require(initialPolicies.isNotEmpty()) { "At least one policy is acceptable" }
    }

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] describes the same validation.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is ValidationParameters && values == other.values

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
     * @return the parameters as text.
     * @since 1.0.0
     */
    override fun toString(): String = "ValidationParameters($values)"
}
