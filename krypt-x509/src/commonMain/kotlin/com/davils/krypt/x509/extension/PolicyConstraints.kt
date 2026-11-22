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

private const val NONE: String = "none"

/**
 * The policy constraints of a certificate authority.
 *
 * @property requireExplicitPolicy after how many certificates a policy is required, or null.
 * @property inhibitPolicyMapping after how many certificates mappings are no longer allowed, or null.
 * @constructor Holds the constraints.
 * @throws IllegalArgumentException if both are null or one is negative.
 * @since 1.0.0
 */
public class PolicyConstraints(
    public val requireExplicitPolicy: Int? = null,
    public val inhibitPolicyMapping: Int? = null,
) {
    init {
        require(requireExplicitPolicy != null || inhibitPolicyMapping != null) { "Policy constraints set a constraint" }
        require(
            (requireExplicitPolicy ?: 0) >= 0 && (inhibitPolicyMapping ?: 0) >= 0,
        ) { "A skip count is not negative" }
    }

    /**
     * Compares both constraints.
     *
     * @param other the other object.
     * @return true if [other] are the same constraints.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is PolicyConstraints &&
        requireExplicitPolicy == other.requireExplicitPolicy &&
        inhibitPolicyMapping == other.inhibitPolicyMapping

    /**
     * Hashes both constraints.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(requireExplicitPolicy, inhibitPolicyMapping).hashCode()

    /**
     * Shows both constraints.
     *
     * @return the constraints as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "PolicyConstraints(requireExplicitPolicy=${requireExplicitPolicy ?: NONE}, inhibitPolicyMapping=${inhibitPolicyMapping ?: NONE})"
}
