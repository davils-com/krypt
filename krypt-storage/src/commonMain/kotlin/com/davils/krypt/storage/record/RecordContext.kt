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

package com.davils.krypt.storage.record

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText

private const val MAXIMUM_LENGTH: Int = 256

/**
 * Where a field lives: its [table], its [column] and its [row]. An encrypted field is bound to its context, so a value
 * copied into another row or column is refused.
 *
 * @property table the table or collection.
 * @property column the column or field.
 * @property row the key of the row or document.
 * @constructor Names a field.
 * @throws IllegalArgumentException if a part is empty or longer than 256 characters.
 * @since 1.0.0
 */
@OptIn(DavilsInternal::class)
public class RecordContext(public val table: String, public val column: String, public val row: String) {
    init {
        require(listOf(table, column, row).all { part -> part.length in 1..MAXIMUM_LENGTH }) {
            "A part of a record context has 1 to $MAXIMUM_LENGTH characters"
        }
    }

    /**
     * Compares every part.
     *
     * @param other the other object.
     * @return true if [other] names the same field.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is RecordContext && listOf(table, column, row) == listOf(other.table, other.column, other.row)

    /**
     * Hashes every part.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(table, column, row).hashCode()

    /**
     * Shows the parts escaped.
     *
     * @return the context as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "RecordContext(${SafeText.text(table)}.${SafeText.text(column)}, row=${SafeText.text(row)})"
}
