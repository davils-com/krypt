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

package com.davils.krypt.core.audit

private const val MAXIMUM_LENGTH: Int = 64

/**
 * The name of an audited action, such as `keyset.key.rotated`: lower case letters, digits, dots and dashes, at most
 * 64 characters. Every module of krypt names its actions in a companion of its own.
 *
 * @property value the name.
 * @since 1.0.0
 */
public class AuditAction(public val value: String) : Comparable<AuditAction> {
    init {
        require(value.length in 1..MAXIMUM_LENGTH) { "The name of an audit action has 1 to $MAXIMUM_LENGTH characters" }
        require(value.all { char -> isAllowed(char) }) {
            "The name of an audit action consists of lower case letters, digits, dots and dashes"
        }
    }

    /**
     * Orders actions by name.
     *
     * @param other the other action.
     * @return the order.
     * @since 1.0.0
     */
    override fun compareTo(other: AuditAction): Int = value.compareTo(other.value)

    /**
     * Compares the names.
     *
     * @param other the other object.
     * @return true if [other] is an action of the same name.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is AuditAction && value == other.value

    /**
     * Hashes the name.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = value.hashCode()

    /**
     * Returns the name.
     *
     * @return the name.
     * @since 1.0.0
     */
    override fun toString(): String = value

    private companion object {
        fun isAllowed(char: Char): Boolean = char in 'a'..'z' || char in '0'..'9' || char == '.' || char == '-'
    }
}
