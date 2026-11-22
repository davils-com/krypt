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

import com.davils.krypt.x509.name.GeneralName

/**
 * The name constraints of a certificate authority: the names every certificate below it must lie within, and the
 * names none may lie within.
 *
 * @property permitted the permitted subtrees, or an empty list for no restriction.
 * @property excluded the excluded subtrees.
 * @constructor Holds the constraints.
 * @throws IllegalArgumentException if both lists are empty.
 * @since 1.0.0
 */
public class NameConstraints(
    public val permitted: List<GeneralName> = emptyList(),
    public val excluded: List<GeneralName> = emptyList(),
) {
    init {
        require(permitted.isNotEmpty() || excluded.isNotEmpty()) { "Name constraints name at least one subtree" }
    }

    /**
     * Compares both lists.
     *
     * @param other the other object.
     * @return true if [other] are the same constraints.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is NameConstraints && permitted == other.permitted && excluded == other.excluded

    /**
     * Hashes both lists.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(permitted, excluded).hashCode()

    /**
     * Shows both lists.
     *
     * @return the constraints as text.
     * @since 1.0.0
     */
    override fun toString(): String = "NameConstraints(permitted=$permitted, excluded=$excluded)"
}
