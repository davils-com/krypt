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

package com.davils.krypt.acme.internal

internal object DnsNames {
    const val WILDCARD: String = "*."
    private const val MAXIMUM_NAME: Int = 253
    private const val MAXIMUM_LABEL: Int = 63
    private const val HYPHEN: Char = '-'

    fun isValid(name: String): Boolean {
        val bare = name.removePrefix(WILDCARD)
        val labels = bare.split('.')
        return name.length <= MAXIMUM_NAME && labels.all { label -> isLabel(label) }
    }

    private fun isLabel(label: String): Boolean {
        val isSized = label.length in 1..MAXIMUM_LABEL
        val hasEdges = isSized && label.first() != HYPHEN && label.last() != HYPHEN
        return hasEdges && label.all { char -> char.isLetterOrDigitAscii() || char == HYPHEN }
    }

    private fun Char.isLetterOrDigitAscii(): Boolean = this in 'a'..'z' || this in 'A'..'Z' || this in '0'..'9'
}
